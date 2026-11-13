# Provider webhook diagnostics

`provider_webhook_source_diagnostics` is a separately runnable registry check with
`{"provider":"stripe|adyen|paypal","paths":["app/code"]}`. It is deliberately
absent from requirement catalogs and customer profiles. It adds no automatic
coverage to MB-0075 or to payment-processing assurance.

The diagnostic reads `composer.lock`, matches the installed SDK method parameter
shape against the supported adapter, records its source SHA-256, and tokenizes
bounded local source without executing it. Package presence is taken from
production `packages`, not `packages-dev`. Missing package/source, an incompatible
API shape, unavailable source or unproven application binding returns UNKNOWN.
Source hashes identify the local bytes inspected; they do not authenticate SDK
integrity or establish that the installed version is safe or supported upstream.

| Provider | Recognized PHP API | Definite source diagnostics |
| --- | --- | --- |
| Stripe | `stripe/stripe-php`: `Stripe\Webhook::constructEvent($payload,$sigHeader,$secret,...)` | Empty literal payload, signature header or endpoint secret. |
| Adyen | `adyen/php-api-library`: `Adyen\Util\HmacSignature::isValidNotificationHMAC($hmacKey,$params)` or `validateHMACSignature($hmacKey,$hmacSign,$webhook)` on a directly constructed, unreassigned local receiver | Empty literal HMAC key; standalone call discarding the boolean verification result. |
| PayPal | Legacy `paypal/rest-api-sdk-php`: `PayPal\Api\VerifyWebhookSignature` | Empty literal required verification-field setter; standalone `post()` discarding the verification-status response. |

Aliases imported with a simple `use Class as Alias` are recognized. Unknown
receivers, grouped imports, indirect dispatch and bindings across control/scope
boundaries are not inferred. Adyen's deprecated `validateHMAC` has historically
different parameter semantics and is intentionally unsupported. Current PayPal
REST postback, self-verification, `paypal/paypal-server-sdk`, JavaScript and custom
wrappers are **unsupported**, rather than silently treated as equivalent to the
legacy SDK. No legacy-SDK migration recommendation follows from this adapter.

FAIL means the exact reported source diagnostic exists. Empty SDK parameters
often trigger rejection or operational errors; they are not evidence that forged
events are accepted. A discarded Adyen boolean or PayPal status is a warning to
investigate control flow, not proof that a protected operation was reached.
Evidence contains relative file, line, method and reason, never source snippets,
request bodies, keys or signatures.

All nonviolating results are UNKNOWN. A recognized verifier call, assigned return
or positive-looking source marker does not prove raw-body/header/secret binding,
valid-event acceptance, invalid-event rejection before side effects, exception
handling, replay protection or correct merchant/account scope. No PASS is emitted.

## Remediation and next verification

- **Stripe:** bind the exact raw request body, `Stripe-Signature` header and the
  secret for that specific endpoint. Investigate exception paths before any state
  change. Calling `constructEvent` solely for its exception behavior is valid and
  is not reported as a discarded-return error. Test valid, altered, missing-header
  and wrong-endpoint-secret requests in an isolated application deployment.
- **Adyen:** use the correct validator for Payments notification items versus
  header-signed webhook types. Require its boolean success before processing;
  keep key rotation compatible with the real provider configuration. Test valid,
  altered, missing-signature and wrong-key fixtures against the actual installed
  SDK and handler, not these source stubs.
- **PayPal:** preserve the configured webhook ID and original request body, and
  require a successful verification status before processing when using postback.
  Test the actual supported integration. PayPal's simulator events cannot use the
  postback verification endpoint; do not mistake a simulator limitation for a
  production verifier failure.

These integration tests need disposable records and a side-effect oracle. This
implementation performs no provider API requests, sends no webhook traffic and
loads no production credentials.

## Primary references inspected 2026-10-18

- [Stripe signature inputs and raw body](https://docs.stripe.com/events/manage-webhook-endpoints#signature-errors)
- [Stripe PHP Webhook implementation](https://github.com/stripe/stripe-php/blob/master/lib/Webhook.php)
- [Adyen webhook HMAC guidance](https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures/)
- [Adyen PHP HmacSignature implementation](https://github.com/Adyen/adyen-php-api-library/blob/main/src/Adyen/Util/HmacSignature.php)
- [PayPal webhook verification methods and simulator limits](https://developer.paypal.com/api/rest/webhooks/rest/)
- [Legacy PayPal VerifyWebhookSignature implementation](https://github.com/paypal/PayPal-PHP-SDK/blob/master/lib/PayPal/Api/VerifyWebhookSignature.php)

The online branch references inform adapter contracts and may change. Runtime
diagnostics therefore inspect installed method shapes instead of assuming the
latest branch matches the deployment. Offline fixtures in
`tests/ProviderWebhookSourceTest.php` use minimal inert SDK-shaped source stubs;
they validate diagnostic parsing, not real provider cryptographic behavior.
