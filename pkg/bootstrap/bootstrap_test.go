package bootstrap_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/aws-structure/pkg/bootstrap"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newPlan(t *testing.T, o bootstrap.Options) *bootstrap.Plan {
	t.Helper()
	p, err := bootstrap.New(o)
	must(t, err)

	return p
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	file := filepath.Join("testdata", name+".golden")
	if *update {
		must(t, os.WriteFile(file, []byte(got), 0o644))
	}
	want, err := os.ReadFile(file)
	must(t, err)
	if string(want) != got {
		t.Errorf("%s differs from the golden (run go test -update to accept):\n%s", name, got)
	}
}

// filler is incompressible-ish text: chained digests in hex.
func filler(n int) string {
	var b strings.Builder
	h := sha256.Sum256([]byte("seed"))
	for b.Len() < n {
		b.WriteString(hex.EncodeToString(h[:]))
		b.WriteByte('\n')
		h = sha256.Sum256(h[:])
	}

	return b.String()[:n]
}

func fullPlan(t *testing.T, o bootstrap.Options) *bootstrap.Plan {
	t.Helper()
	p := newPlan(t, o)
	must(t, p.Add(
		bootstrap.Compose("base",
			bootstrap.Package{Name: "jq"},
			bootstrap.Package{Name: "awscli"},
			bootstrap.File{Path: "/etc/example/app.conf", Content: "listen = :8080\n"},
			bootstrap.File{Path: "/etc/example/tls.b64", Mode: "0640", Owner: "root:app", Encoding: "base64", Content: "aGVsbG8K"},
		),
		bootstrap.Compose("app",
			bootstrap.Package{Name: "jq"},
			bootstrap.Binary{Name: "app", Dest: "/usr/local/bin/app", PerArch: map[string]bootstrap.Source{
				"arm64": {URL: "https://example.com/app-arm64", SHA256: digest},
				"amd64": {URL: "https://example.com/app-amd64", SHA256: strings.Repeat("ab", 32)},
			}},
			bootstrap.Artifact{URL: "https://example.com/tool.sh", SHA256: digest, Dest: "/opt/tool/run.sh", Run: true},
			bootstrap.SSMSecret{Parameter: "/example/app/token", Dest: "/run/app/token.env", Format: bootstrap.FormatEnv, Var: "APP_TOKEN", Owner: "app"},
			bootstrap.Unit{Name: "app", Content: "[Service]\nExecStart=/usr/local/bin/app\n", Enable: true, Start: true},
			bootstrap.Step{Name: "greet", Order: 10, Script: "echo hello\n"},
			bootstrap.Step{Name: "every boot", Phase: bootstrap.PhaseBoot, Script: "echo boot\n"},
		),
	))

	return p
}

func TestGoldenPlain(t *testing.T) {
	r, err := fullPlan(t, bootstrap.Options{}).Render()
	must(t, err)
	golden(t, "plain", r.CloudConfig)
	if r.Gzipped || string(r.UserData) != r.CloudConfig {
		t.Error("a small plan must not be compressed")
	}
	if got := strings.Join(r.SSMParameters, ","); got != "/example/app/token" {
		t.Errorf("ssm parameters = %q", got)
	}
}

func TestGoldenLifecycle(t *testing.T) {
	p := fullPlan(t, bootstrap.Options{Lifecycle: &bootstrap.Lifecycle{ASGName: "example-asg", HookName: "example-hook"}})
	r, err := p.Render()
	must(t, err)
	golden(t, "lifecycle", r.CloudConfig)
	if !strings.Contains(r.CloudConfig, "--lifecycle-action-result ABANDON") {
		t.Error("no ABANDON in a plan with a lifecycle")
	}
}

func TestGoldenSpill(t *testing.T) {
	o := bootstrap.Options{
		Objects: &bootstrap.ObjectStore{Bucket: "example-config", Prefix: "/appliance/"},
		Limit:   9000, SoftLimit: 5000, Lifecycle: &bootstrap.Lifecycle{ASGName: "example-asg", HookName: "example-hook"},
	}
	p := fullPlan(t, o)
	big := filler(14000)
	must(t, p.AddItems(bootstrap.File{Path: "/etc/example/big.json", Content: big}, bootstrap.File{Path: "/etc/example/small.txt", Content: "small content\n"}))
	r, err := p.Render()
	must(t, err)
	golden(t, "spill", r.CloudConfig)
	if len(r.Objects) != 1 || string(r.Objects[0].Content) != big {
		t.Fatalf("want the big file as the one object, got %d objects", len(r.Objects))
	}
	sum := sha256.Sum256([]byte(big))
	if want := "appliance/config/" + hex.EncodeToString(sum[:]) + ".json"; r.Objects[0].Key != want {
		t.Errorf("key = %q, want %q", r.Objects[0].Key, want)
	}
	if !strings.Contains(r.CloudConfig, "/etc/example/small.txt") || strings.Contains(r.CloudConfig, big[:64]) {
		t.Error("the small file must stay inline and the big one must leave the user-data")
	}
	if r.Size > o.Limit {
		t.Errorf("size %d over the limit", r.Size)
	}
}

func TestExplicitObjectDelivery(t *testing.T) {
	p := newPlan(t, bootstrap.Options{Objects: &bootstrap.ObjectStore{Bucket: "example-config"}})
	must(t, p.AddItems(bootstrap.File{Path: "/etc/x", Content: "x", Delivery: bootstrap.DeliveryObject}))
	r, err := p.Render()
	must(t, err)
	if len(r.Objects) != 1 || !strings.HasPrefix(r.Objects[0].Key, "config/") || !strings.HasSuffix(r.Objects[0].Key, ".bin") {
		t.Errorf("objects = %+v", r.Objects)
	}
	if err := newPlan(t, bootstrap.Options{}).AddItems(bootstrap.File{Path: "/etc/x", Delivery: bootstrap.DeliveryObject}); err == nil {
		t.Error("an object file without an object store must be refused")
	}
}

func TestGzip(t *testing.T) {
	p := newPlan(t, bootstrap.Options{})
	must(t, p.AddItems(bootstrap.File{Path: "/etc/example/log.txt", Content: strings.Repeat("a line of text\n", 1500)}))
	r, err := p.Render()
	must(t, err)
	golden(t, "gzip-plain", r.CloudConfig)
	if !r.Gzipped || !bytes.HasPrefix(r.UserData, []byte{0x1f, 0x8b}) {
		t.Fatal("a plan over the soft limit must be gzipped")
	}
	zr, err := gzip.NewReader(bytes.NewReader(r.UserData))
	must(t, err)
	back, err := io.ReadAll(zr)
	must(t, err)
	if string(back) != r.CloudConfig {
		t.Error("gunzip does not give back the cloud-config")
	}
	if len(r.CloudConfig) <= bootstrap.DefaultLimit || r.Size > bootstrap.DefaultLimit {
		t.Errorf("want text over and compressed under the limit, got %d and %d", len(r.CloudConfig), r.Size)
	}

	never := newPlan(t, bootstrap.Options{Gzip: bootstrap.GzipNever})
	must(t, never.AddItems(bootstrap.File{Path: "/etc/example/log.txt", Content: strings.Repeat("a line of text\n", 1500)}))
	if _, err := never.Render(); err == nil {
		t.Error("over the limit with GzipNever and no objects must fail")
	}

	always := fullPlan(t, bootstrap.Options{Gzip: bootstrap.GzipAlways})
	ra, err := always.Render()
	must(t, err)
	if !ra.Gzipped {
		t.Error("GzipAlways did not compress")
	}
}

func TestOverLimit(t *testing.T) {
	p := newPlan(t, bootstrap.Options{Objects: &bootstrap.ObjectStore{Bucket: "example-config"}, Limit: 600, SoftLimit: 300})
	must(t, p.AddItems(bootstrap.File{Path: "/etc/a", Content: filler(2000), Delivery: bootstrap.DeliveryInline}))
	if _, err := p.Render(); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("an inline file over the limit must fail, got %v", err)
	}
}

func TestDeterministic(t *testing.T) {
	for i := 0; i < 20; i++ {
		a, err := fullPlan(t, bootstrap.Options{}).Render()
		must(t, err)
		b, err := fullPlan(t, bootstrap.Options{}).Render()
		must(t, err)
		if !bytes.Equal(a.UserData, b.UserData) {
			t.Fatal("two renders of the same plan differ")
		}
		again, err := fullPlan(t, bootstrap.Options{}).Render()
		must(t, err)
		if !bytes.Equal(a.UserData, again.UserData) {
			t.Fatal("a third render differs")
		}
	}
	p := fullPlan(t, bootstrap.Options{})
	a, _ := p.Render()
	b, _ := p.Render()
	if !bytes.Equal(a.UserData, b.UserData) {
		t.Error("rendering the same plan twice differs")
	}
}

func TestConflicts(t *testing.T) {
	cases := map[string][]bootstrap.Fragment{
		"path": {
			bootstrap.Compose("one", bootstrap.File{Path: "/etc/x", Content: "a"}),
			bootstrap.Compose("two", bootstrap.File{Path: "/etc/x", Content: "a"}),
		},
		"unit": {
			bootstrap.Compose("one", bootstrap.Unit{Name: "svc", Content: "[Service]\n"}),
			bootstrap.Compose("two", bootstrap.Unit{Name: "svc.service", Content: "[Service]\n"}),
		},
		"unit versus file": {
			bootstrap.Compose("one", bootstrap.Unit{Name: "svc", Content: "[Service]\n"}),
			bootstrap.Compose("two", bootstrap.File{Path: "/etc/systemd/system/svc.service", Content: "x"}),
		},
		"drop-in twice": {
			bootstrap.Compose("one", bootstrap.Unit{Name: "svc", DropIn: true, Content: "[Service]\n"}),
			bootstrap.Compose("two", bootstrap.Unit{Name: "svc", DropIn: true, Content: "[Service]\n"}),
		},
	}
	for name, frags := range cases {
		err := newPlan(t, bootstrap.Options{}).Add(frags...)
		if err == nil || !strings.Contains(err.Error(), `"one"`) || !strings.Contains(err.Error(), `"two"`) {
			t.Errorf("%s: want a conflict naming both fragments, got %v", name, err)
		}
	}
	p := newPlan(t, bootstrap.Options{})
	must(t, p.Add(
		bootstrap.Compose("one", bootstrap.Unit{Name: "svc", Content: "[Service]\n"}),
		bootstrap.Compose("two", bootstrap.Unit{Name: "svc", DropIn: true, Content: "[Service]\n"}),
		bootstrap.Compose("three", bootstrap.Package{Name: "jq"}),
		bootstrap.Compose("four", bootstrap.Package{Name: "jq"}),
	))
}

func TestRefusals(t *testing.T) {
	mips := map[string]bootstrap.Source{"mips": {URL: "https://example.com/x", SHA256: digest}}
	bad := map[string]bootstrap.Item{
		"relative path":         bootstrap.File{Path: "etc/x"},
		"dotdot":                bootstrap.File{Path: "/etc/../x"},
		"bad mode":              bootstrap.File{Path: "/etc/x", Mode: "rw"},
		"bad base64":            bootstrap.File{Path: "/etc/x", Encoding: "base64", Content: "!!"},
		"unknown encoding":      bootstrap.File{Path: "/etc/x", Encoding: "gz"},
		"http artifact":         bootstrap.Artifact{URL: "http://example.com/x", SHA256: digest, Dest: "/x"},
		"credentials in url":    bootstrap.Artifact{URL: "https://user:pw@example.com/x", SHA256: digest, Dest: "/x"},
		"presigned url":         bootstrap.Artifact{URL: "https://example.com/x?X-Amz-Signature=1", SHA256: digest, Dest: "/x"},
		"no digest":             bootstrap.Artifact{URL: "https://example.com/x", Dest: "/x"},
		"upper-case digest":     bootstrap.Artifact{URL: "https://example.com/x", SHA256: strings.ToUpper(digest), Dest: "/x"},
		"binary without builds": bootstrap.Binary{Name: "x", Dest: "/x"},
		"binary arch":           bootstrap.Binary{Name: "x", Dest: "/x", PerArch: mips},
		"secret outside /run":   bootstrap.SSMSecret{Parameter: "/example/p", Dest: "/etc/p"},
		"secret in /run itself": bootstrap.SSMSecret{Parameter: "/example/p", Dest: "/run/p"},
		"secret mode":           bootstrap.SSMSecret{Parameter: "/example/p", Dest: "/run/x/p", Mode: "0644"},
		"secret param":          bootstrap.SSMSecret{Parameter: "relative", Dest: "/run/x/p"},
		"env without var":       bootstrap.SSMSecret{Parameter: "/example/p", Dest: "/run/x/p", Format: bootstrap.FormatEnv},
		"raw with var":          bootstrap.SSMSecret{Parameter: "/example/p", Dest: "/run/x/p", Var: "X"},
		"empty step":            bootstrap.Step{Name: "x"},
		"multi-line step name":  bootstrap.Step{Name: "x\ny", Script: "true"},
		"package":               bootstrap.Package{Name: "Bad Name"},
		"empty unit":            bootstrap.Unit{Name: "x"},
	}
	for name, it := range bad {
		if err := newPlan(t, bootstrap.Options{}).AddItems(it); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
	for name, o := range map[string]bootstrap.Options{
		"soft over hard": {Limit: 100, SoftLimit: 200},
		"bucket":         {Objects: &bootstrap.ObjectStore{Bucket: "Bad_Bucket"}},
		"prefix":         {Objects: &bootstrap.ObjectStore{Bucket: "example-config", Prefix: "a/../b"}},
		"lifecycle":      {Lifecycle: &bootstrap.Lifecycle{ASGName: "only"}},
	} {
		if _, err := bootstrap.New(o); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

func TestNoSecretsAnywhere(t *testing.T) {
	// Built from pieces so this file holds no token-shaped literal.
	secrets := map[string]string{
		"private key":    "-----BEGIN " + "RSA PRIVATE KEY-----\nabc\n",
		"aws access key": "AK" + "IA" + strings.Repeat("A", 16),
		"github token":   "gh" + "p_" + strings.Repeat("a", 36),
		"slack token":    "xo" + "xb-" + "1234567890-abcdef",
		"aws secret":     "aws_secret_access_key = " + strings.Repeat("a", 40),
	}
	for name, s := range secrets {
		for where, it := range map[string]bootstrap.Item{
			"file":     bootstrap.File{Path: "/etc/x", Content: s},
			"b64 file": bootstrap.File{Path: "/etc/x", Encoding: "base64", Content: b64(s)},
			"step":     bootstrap.Step{Name: "x", Script: "echo " + s},
			"unit":     bootstrap.Unit{Name: "x", Content: s},
		} {
			if err := newPlan(t, bootstrap.Options{}).AddItems(it); err == nil {
				t.Errorf("%s in a %s: want a refusal", name, where)
			} else if strings.Contains(err.Error(), s) {
				t.Errorf("%s in a %s: the error repeats the secret", name, where)
			}
		}
		if err := newPlan(t, bootstrap.Options{}).Add(bootstrap.UnitFragment{LoadToken: s}.Fragment("x", bootstrap.RunAuto)); err == nil {
			t.Errorf("%s in a unit fragment: want a refusal", name)
		}
		if _, err := bootstrap.Verbatim("#cloud-config\n# "+s+"\n", 0); err == nil {
			t.Errorf("%s in verbatim user-data: want a refusal", name)
		}
	}
}

func TestSecretValueNeverInOutput(t *testing.T) {
	r, err := fullPlan(t, bootstrap.Options{}).Render()
	must(t, err)
	for _, want := range []string{"--with-decryption", "/example/app/token", "install -d -m 0700", "umask 077", "chmod 0600"} {
		if !strings.Contains(r.CloudConfig, want) {
			t.Errorf("secret step lacks %q", want)
		}
	}
	for _, bad := range []string{"set -x", "echo \"$v\"", "echo $v"} {
		if strings.Contains(r.CloudConfig, bad) {
			t.Errorf("a script that can print the secret: %q", bad)
		}
	}
}

func TestUnitFragment(t *testing.T) {
	f := bootstrap.UnitFragment{
		Install:       "install_it() { true; }\ninstall_it\n",
		Unit:          "[Service]\nExecStart=/usr/local/bin/conn\n",
		UnitPath:      "/etc/systemd/system/conn.service",
		LoadToken:     "umask 077\ntrue\n",
		Start:         "systemctl daemon-reload\nsystemctl start conn\n",
		SSMParameters: []string{"/example/conn/token", "/example/a"},
	}
	auto := newPlan(t, bootstrap.Options{})
	must(t, auto.Add(f.Fragment("conn", bootstrap.RunAuto)))
	ra, err := auto.Render()
	must(t, err)
	golden(t, "unitfragment-auto", ra.CloudConfig)
	if got := strings.Join(ra.SSMParameters, ","); got != "/example/a,/example/conn/token" {
		t.Errorf("parameters = %q", got)
	}
	i, l, s := strings.Index(ra.CloudConfig, "conn install"), strings.Index(ra.CloudConfig, "conn load token"), strings.Index(ra.CloudConfig, "conn start")
	if i <= 0 || i >= l || l >= s {
		t.Errorf("want install, load token, start in that order, got %d %d %d", i, l, s)
	}

	manual := newPlan(t, bootstrap.Options{})
	must(t, manual.Add(f.Fragment("conn", bootstrap.RunManual)))
	rm, err := manual.Render()
	must(t, err)
	if strings.Contains(rm.CloudConfig, "conn start") || strings.Contains(rm.CloudConfig, "load token") || !strings.Contains(rm.CloudConfig, "conn install") {
		t.Error("manual mode must install and write the unit only")
	}
	if len(rm.SSMParameters) != 2 {
		t.Error("manual mode must still report the parameters")
	}

	if err := newPlan(t, bootstrap.Options{}).Add(bootstrap.UnitFragment{Unit: "[Service]\n"}.Fragment("x", bootstrap.RunAuto)); err == nil {
		t.Error("a unit without a path must be refused")
	}
}

func TestVerbatim(t *testing.T) {
	in := "#!/bin/bash\r\necho  odd   spacing\n\n\ttabs and no trailing newline"
	r, err := bootstrap.Verbatim(in, 0)
	must(t, err)
	if string(r.UserData) != in || r.Gzipped || len(r.Objects) != 0 || r.Size != len(in) {
		t.Error("verbatim must carry the text unchanged")
	}
	if _, err := bootstrap.Verbatim(strings.Repeat("x", 100), 50); err == nil {
		t.Error("verbatim over the limit must fail")
	}
}

func b64(s string) string {
	var b bytes.Buffer
	enc := base64Encoder(&b)
	_, _ = enc.Write([]byte(s))
	_ = enc.Close()

	return b.String()
}

// allowlisted keys of the cloud-config modules the composer emits.
var (
	topKeys  = map[string]bool{"packages": true, "write_files": true, "bootcmd": true, "runcmd": true}
	fileKeys = map[string]bool{"path": true, "owner": true, "permissions": true, "encoding": true, "defer": true, "content": true}
)

func TestCloudConfigShape(t *testing.T) {
	_, haveBash := exec.LookPath("bash")
	opts := bootstrap.Options{
		Objects: &bootstrap.ObjectStore{Bucket: "example-config", Prefix: "appliance"},
		Limit:   9000, SoftLimit: 5000, Lifecycle: &bootstrap.Lifecycle{ASGName: "example-asg", HookName: "example-hook"},
	}
	for name, p := range map[string]*bootstrap.Plan{"plain": fullPlan(t, bootstrap.Options{}), "spill": fullPlan(t, opts)} {
		if name == "spill" {
			must(t, p.AddItems(bootstrap.File{Path: "/etc/example/big.json", Content: filler(14000)}))
		}
		r, err := p.Render()
		must(t, err)
		if !strings.HasPrefix(r.CloudConfig, "#cloud-config\n") {
			t.Fatalf("%s: no #cloud-config header", name)
		}
		var doc map[string]any
		must(t, yaml.Unmarshal([]byte(r.CloudConfig), &doc))
		for k := range doc {
			if !topKeys[k] {
				t.Errorf("%s: unexpected top-level key %q", name, k)
			}
		}
		for _, f := range doc["write_files"].([]any) {
			for k := range f.(map[string]any) {
				if !fileKeys[k] {
					t.Errorf("%s: unexpected write_files key %q", name, k)
				}
			}
		}
		for _, list := range []string{"bootcmd", "runcmd"} {
			cmds, _ := doc[list].([]any)
			if len(cmds) > 0 && cmds[0] != "set -e" {
				t.Errorf("%s: %s does not start with set -e", name, list)
			}
			for _, c := range cmds[min(1, len(cmds)):] {
				argv, ok := c.([]any)
				if !ok || len(argv) != 3 || argv[0] != "bash" {
					t.Fatalf("%s: %s entry %v is not a bash -ec triple", name, list, c)
				}
				if haveBash == nil {
					out, err := exec.Command("bash", "-n", "-c", argv[2].(string)).CombinedOutput()
					if err != nil {
						t.Errorf("%s: %s script does not parse: %v\n%s\n%s", name, list, err, out, argv[2])
					}
				}
			}
		}
	}
}

func base64Encoder(w io.Writer) io.WriteCloser { return base64.NewEncoder(base64.StdEncoding, w) }
