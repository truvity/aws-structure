package alerting

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/sns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Delivery is how a topic reaches the receiver besides, or instead of, its
// HTTPS endpoint. The zero value changes nothing: every topic keeps its HTTPS
// subscription and gets no other.
//
// The queue is the receiver's (an SQS queue its pods long-poll); the topic is
// the caller's. The subscription lives in the topic's account and region, so
// the queue may be in another account or region: the queue's own policy must
// then allow the topic (aws:SourceArn), which is the queue owner's side.
type Delivery struct {
	// QueueARN, when set, subscribes the queue to every topic this package
	// (or package cost) owns, with protocol sqs and raw message delivery OFF:
	// the receiver verifies the SNS envelope's signature, which only the
	// wrapped message carries.
	QueueARN string
	// DisableHTTPS removes the HTTPS subscriptions (and so the need for an
	// Endpoint). It is the last step of a cutover: it needs QueueARN, since a
	// topic with no subscription alerts nobody. Destroying a subscription is
	// a deploy-time change; the receiver's queue should already carry the
	// traffic.
	DisableHTTPS bool
}

var queueARNPattern = regexp.MustCompile(`^arn:([a-z-]+):sqs:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]{1,80}(\.fifo)?$`)

// Validate reports every problem with d at once, or returns nil.
func (d Delivery) Validate(partition string) error {
	var errs []error

	if d.QueueARN != "" {
		m := queueARNPattern.FindStringSubmatch(d.QueueARN)

		switch {
		case m == nil:
			errs = append(errs, fmt.Errorf("delivery: QueueARN %q is not an SQS queue ARN", d.QueueARN))
		case m[1] != partition:
			errs = append(errs, fmt.Errorf("delivery: QueueARN %q is not in partition %q", d.QueueARN, partition))
		}
	}

	if d.DisableHTTPS && d.QueueARN == "" {
		errs = append(errs, errors.New("delivery: DisableHTTPS needs QueueARN: a topic with no subscription alerts nobody"))
	}

	return errors.Join(errs...)
}

// SubscribeQueue creates the SQS subscription of a topic when d names a queue,
// and does nothing otherwise. Pass the topic's own provider.
func (d Delivery) SubscribeQueue(ctx *pulumi.Context, name string, topic pulumi.StringInput, opts ...pulumi.ResourceOption) error {
	if d.QueueARN == "" {
		return nil
	}

	if _, err := sns.NewTopicSubscription(ctx, name, &sns.TopicSubscriptionArgs{
		Topic:    topic,
		Protocol: pulumi.String("sqs"),
		Endpoint: pulumi.String(d.QueueARN),
		// The receiver verifies the SNS signature of the envelope.
		RawMessageDelivery: pulumi.Bool(false),
	}, opts...); err != nil {
		return fmt.Errorf("create SQS subscription %s: %w", name, err)
	}

	return nil
}
