---
title: A CDN in front of a cloud deployment
nav_order: 18
---

# A CDN in front of a cloud deployment

Every cloud deployment pattern in `deploy/` can put its provider's content
delivery network in front of the load balancer. The edge ends a browser's TCP
connection close to the browser and carries the request over the provider's
network. On `testidp` in AWS this turned a path that stalled for 9 to 70
seconds on about one fetch in six into 30 fetches out of 30 under 1.5 seconds.

| Pattern | CDN | Turned on by | Where it is |
|---|---|---|---|
| AWS, one region | CloudFront | `cloudfront_enabled`, `direct_hostname` | `deploy/aws/environment/cloudfront.tf` |
| AWS, several regions (cells) | one CloudFront distribution, held by the primary cell | the same two settings in `envs/<env>.tfvars` | the same file, and `dns_cells.tf` |
| GCP, one region | Cloud CDN behind a global external Application Load Balancer | `cdn_enabled`, `direct_hostname` | `deploy/gcp/environment/cdn.tf` |
| Azure, one or several regions | Azure Front Door Standard | `cdn_enabled`, and `direct_hostname` (in the cells file for several regions) | `deploy/azure/environment/frontdoor.tf` |
| AWS and GCP together (`testidpmc`) | the AWS primary cell's CloudFront distribution, in front of both clouds' cells | `cloudfront_enabled`, `cdn_enabled`, and `direct_hostname` in the cells file | `deploy/multicloud/interconnect/routing.tf` |

**Only AWS single-region (`testidp`) has been applied.** The other patterns are
written and checked offline (`terraform validate` and a mocked `terraform test`
render). No `terraform plan` has been run against GCP, Azure or the multi-cell
and multi-cloud AWS environments.

## Two names

A CDN ends TLS, so a client certificate never reaches a node through it, and it
carries only HTTP. Every pattern therefore has two names:

| Use | Name |
|---|---|
| Browsers, OAuth and OpenID Connect clients, the issuer | `public_hostname`, at the CDN |
| Client certificates (certificate sign-in, RFC 8705), Kerberos, LDAP, SPIFFE, CRLs and OCSP | `direct_hostname`, at the load balancer |

With several regions, the direct name is the routing tree that used to be the
public name (Route 53 geolocation and latency or geoproximity records, or Traffic
Manager on Azure). The CDN uses the direct name as its origin, so an edge reaches
the nearest healthy region. The tree is resolved from the edge, not from the
browser, so a pinned country is matched by where the edge is. The service, not
DNS, decides where a person's data is served, so a request that lands in the
wrong region is relayed or refused there as before.

New certificates name the direct host in their CRL and OCSP addresses. The nodes'
own certificate carries both names.

## What the edge caches

Only the static surfaces: every `*.js` and `*.css` file and everything under
`/web/` (and `/realm/<realm>/web/`). The edge follows the service's own
`Cache-Control`, so an answer marked `no-store` or `no-cache` is never kept.
Every other answer — API calls, protocol endpoints, documents carrying keys — is
neither cached nor compressed at the edge, because compressing a secret beside
text the caller chose is the BREACH attack. No error response is cached.

## What the service is told

| | AWS (CloudFront) | GCP (Cloud CDN) | Azure (Front Door) |
|---|---|---|---|
| Allowlist (`allowed_cidrs`) at the edge | AWS WAF, IPv4 | Cloud Armor, at the backend and at the edge | Front Door WAF on the connecting address |
| `X-Forwarded-Host` and `-Proto` | set by the distribution, replacing a caller's | replaced by the URL map | set by Front Door; only the public name is served |
| The edge's addresses | `global.edgeProxies` and `global.trustedProxies` | `global.trustedProxies` only | `global.edgeProxies` and `global.trustedProxies` |
| Origin secret (`global.edgeSecret`, header `X-Origin-Verify`) | yes | no | yes |

An origin secret is needed where the provider's edge addresses are shared by
every one of its customers, so that another customer's CDN pointed at this load
balancer is refused (error code `STS-CORE-0165`). Google's front ends reach a
backend only from a load balancer in the same project, and every Google health
check comes from those same addresses without any header, so GCP trusts them as
proxies and does not ask them for a secret.

A node that calls its own public name does not go through the edge: inside the
node the name points at its own load balancer.

## Limits

* Certificate sign-in and RFC 8705 mutual TLS work only at the direct name.
* CloudFront limits a URL to 8,192 bytes and an origin's first byte to 60
  seconds; the GCP and Azure patterns use a 60-second origin timeout too.
* The AWS allowlist is IPv4 only, so IPv6 is off at CloudFront.
* The origin secret is part of the CDN's configuration, so anybody who can read
  that configuration can read it.

See [A cluster in AWS](aws-cluster.md) for running the AWS patterns and
[Several regions (cells)](cells.md) for how cells are routed.
