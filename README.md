## Getting Started

Set Node.js 20.9+ before building or deploying.

### Optional webhook.site debugging

If you set `WEBHOOK_SITE_URL`, the app will:

- send one POST request during `npm run build`
- send one POST request each time the dynamic page is rendered at runtime
- write build webhook metadata to `public/build-metadata.json`

Example:

```bash
WEBHOOK_SITE_URL="https://webhook.site/your-id" npm run build
```

This is for debugging outbound IP and request timing. The dashboard still uses the IP lookup services for the displayed external IP.

deploy it -
thanks
