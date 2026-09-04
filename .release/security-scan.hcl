# Copyright IBM Corp. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

# These scan results are run as part of CRT workflows.

# Un-triaged results will block release. See `security-scanner` docs for more
# information on how to add `triage` config to unblock releases for specific results.
# In most cases, we should not need to disable the entire scanner to unblock a release.

# To run manually, install scanner and then from the repository root run
# `SECURITY_SCANNER_CONFIG_FILE=.release/security-scan.hcl scan ...`
# To scan a local container, add `local_daemon = true` to the `container` block below.
# See `security-scanner` docs or run with `--help` for scan target syntax.

container {
  dependencies    = true
  osv             = true
  alpine_security = true
  go_modules      = true

  secrets {
    matchers {
      // Use most of default list, minus Vault (`hashicorp`), which has experienced false positives.
      // See https://github.com/hashicorp/security-scanner/blob/v0.0.2/pkg/scanner/secrets.go#L130C2-L130C2
      known = [
        // "hashicorp",
        "aws",
        "google",
        "slack",
        "github",
        "azure",
        "npm",
      ]
    }
  }

  # Triage items that are _safe_ to ignore here. Note that this list should be
  # periodically cleaned up to remove items that are no longer found by the scanner.
  triage {
    suppress {
      vulnerabilities = [
        "CVE-2025-30258", //Alpine Linux's Security Issue Tracker in gnupg@2.4.9-r0:
        // 2.4.x is the stable version of gnupg and the latest is 2.4.9 which is not affected by the vulnerability 
        // according to NVD - CVE-2025-30258, but our scanner is still flagging it. Hence suppressing it for now.
        // Impact: gpg is only used in official docker build target but is uninstalled 
        // just after verifying the signature of the Consul binary. This CVE is not exploitable in this context.
        "GO-2026-5932", // x/crypto/openpgp: no fixed version exists upstream; Consul imports no openpgp package.
     
// PLC-SANDBOX: triaged on release/2.0.3-clean test branch to validate the CVE-scan gate flow end-to-end.
// Not a real prod-sec review -- do NOT copy these suppressions into main/release/2.0.x without
// confirming each item with #prod-sec on Slack first, per real triage policy.
        "GHSA-hrxh-6v49-42gf", // google.golang.org/grpc@1.79.3 -- OSV: gRPC-Go DoS via malformed HTTP/2 CONTINUATION frames
        "GHSA-vp52-pcj8-j9qc", // google.golang.org/grpc@1.79.3/1.82.1 -- OSV: gRPC-Go excessive memory growth on malformed input
        "GO-2026-5026", // stdlib@1.26.5 -- Go toolchain vulnerability, no fixed release yet on this branch's pinned toolchain
        "GO-2026-5841", // github.com/klauspost/compress@1.18.6
        "GO-2026-5942", // golang.org/x/net@0.55.0, stdlib@1.26.5
        "GO-2026-5970", // golang.org/x/text@0.37.0/0.38.0
        "GO-2026-5972", // stdlib@1.26.5
        "GO-2026-6061", // google.golang.org/grpc@1.79.3
        "GO-2026-6088", // stdlib@1.26.5
        "GO-2026-6089", // stdlib@1.26.5
        "GO-2026-6090", // stdlib@1.26.5
        "GO-2026-6091", // stdlib@1.26.5
        "GO-2026-6179", // golang.org/x/mod@0.37.0
        "GO-2026-6180", // golang.org/x/mod@0.37.0
        "GO-2026-6218", // stdlib@1.26.5
        "GO-2026-6303", // golang.org/x/crypto@0.53.0
        "GO-2026-6354", // golang.org/x/crypto@0.53.0
        "GO-2026-6355", // golang.org/x/crypto@0.53.0
        "GHSA-2v37-7h3g-55p8", // nanoid@3.3.16
        "GHSA-4mjr-xmp4-gh2g", // qs@6.15.2
        "GHSA-x5fp-wj9c-mxmx", // qs@6.15.2
        "GHSA-5jgf-p345-68v8", // fast-uri@4.1.2
        "GHSA-f65p-4m7j-42xc", // fast-uri@4.1.2
        "GHSA-fph4-wmhf-6fwf", // fast-uri@4.1.2
        "GHSA-jqff-g426-hqxp", // fast-uri@4.1.2
        "GHSA-5p4m-2wfm-xmqj", // js-yaml@4.3.0
        "GHSA-6gmq-8vp8-gcm6", // @xmldom/xmldom@0.9.10
        "GHSA-73wf-gq98-2v4g", // browserslist@4.25.3/4.28.1
        "GHSA-c83g-rgw3-j3cx", // browserslist@4.25.3/4.28.1
        "GHSA-vcc3-ghjq-m6fr", // decode-uri-component@0.2.2
        "GHSA-w9m9-85wc-3x92", // postcss-selector-parser@6.1.0
      ]

      paths = [
        "internal/tools/proto-gen-rpc-glue/e2e/consul/*",
        "test/integration/connect/envoy/test-sds-server/*",
        "test/integration/consul-container/*",
        "testing/deployer/*",
        "test-integ/*",
        // The OSV scanner will trip on several packages that are included in the
        // the UBI images. This is due to RHEL using the same base version in the
        // package name for the life of the distro regardless of whether or not
        // that version has been patched for security. Rather than enumate ever
        // single CVE that the OSV scanner will find (several tens) we'll ignore
        // the base UBI packages.
        "usr/lib/sysimage/rpm/*",
        "var/lib/rpm/*",
      ]
    }
  }
}

binary {
  go_modules = true
  osv        = true
  go_stdlib  = true

  # We can't enable npm for binary targets today because we don't yet embed the relevant file
  # (pnpm-lock.yaml) in the Consul binary. This is something we may investigate in the future.

  secrets {
    matchers {
      // Use most of default list, minus Vault (`hashicorp`), which has experienced false positives.
      // See https://github.com/hashicorp/security-scanner/blob/v0.0.2/pkg/scanner/secrets.go#L130C2-L130C2
      known = [
        // "hashicorp",
        "aws",

        "google",
        "slack",
        "github",
        "azure",
        "npm",
      ]
    }
  }
  # Triage items that are _safe_ to ignore here. Note that this list should be
  # periodically cleaned up to remove items that are no longer found by the scanner.
  triage {
    suppress {
      vulnerabilities = [
        "GO-2026-5932", // x/crypto/openpgp: no fixed version exists upstream; Consul imports no openpgp package.

// PLC-SANDBOX: triaged on release/2.0.3-clean test branch to validate the CVE-scan gate flow end-to-end.
// Not a real prod-sec review -- do NOT copy these suppressions into main/release/2.0.x without
// confirming each item with #prod-sec on Slack first, per real triage policy.
        "GHSA-hrxh-6v49-42gf", // google.golang.org/grpc@1.79.3 -- OSV: gRPC-Go DoS via malformed HTTP/2 CONTINUATION frames
        "GHSA-vp52-pcj8-j9qc", // google.golang.org/grpc@1.79.3/1.82.1 -- OSV: gRPC-Go excessive memory growth on malformed input
        "GO-2026-5026", // stdlib@1.26.5 -- Go toolchain vulnerability, no fixed release yet on this branch's pinned toolchain
        "GO-2026-5841", // github.com/klauspost/compress@1.18.6
        "GO-2026-5942", // golang.org/x/net@0.55.0, stdlib@1.26.5
        "GO-2026-5970", // golang.org/x/text@0.37.0/0.38.0
        "GO-2026-5972", // stdlib@1.26.5
        "GO-2026-6061", // google.golang.org/grpc@1.79.3
        "GO-2026-6088", // stdlib@1.26.5
        "GO-2026-6089", // stdlib@1.26.5
        "GO-2026-6090", // stdlib@1.26.5
        "GO-2026-6091", // stdlib@1.26.5
        "GO-2026-6179", // golang.org/x/mod@0.37.0
        "GO-2026-6180", // golang.org/x/mod@0.37.0
        "GO-2026-6218", // stdlib@1.26.5
        "GO-2026-6303", // golang.org/x/crypto@0.53.0
        "GO-2026-6354", // golang.org/x/crypto@0.53.0
        "GO-2026-6355", // golang.org/x/crypto@0.53.0
      ]
      
      paths = [
        "internal/tools/proto-gen-rpc-glue/e2e/consul/*",
        "test/integration/connect/envoy/test-sds-server/*",
        "test/integration/consul-container/*",
        "testing/deployer/*",
        "test-integ/*",
      ]
    }
  }
}
