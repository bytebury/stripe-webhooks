# stripe-webhooks
Listens to basic webhooks from Stripe. Particularly those that are common for subscribing and cancelling a subscription from Stripe. However, you can also incorporate all of the hooks by using the `StripeEvent::Unknown` enum.

## Usage
```rs
pub async handler(headers: HeaderMap, body: String) {
    let stripe_events = StripeListener::from_env();
    let stripe_event = match stripe_events.process(&headers, &body) {
        Ok(event) => event,
        Err(e) => {
            eprintln!("Failed to process webhook: {:?}", e)
            return;
        };
    };

    match stripe_event {
        StripeEvent::CheckoutSessionCompleted(ev) => {
            println!("Checkout session completed: {:?}", ev);
        },
        StripeEvent::CustomerSubscriptionDeleted(obj) => {
            println!("Customer subscription deleted: {:?}", obj);
        }
        StripeEvent::Unknown(obj) => {
            println!("Unknown Stripe event: {:?}", obj);
        }
    }
}
```
