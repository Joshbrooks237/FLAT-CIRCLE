/**
 * Layer 6 — Syntactic Mimicry
 *
 * Spoof server headers, error pages, and technology fingerprints.
 * The attacker's entire toolset is aimed at the wrong target from the first probe.
 */

import type { Layer6Config } from "@flat-circle/core/types";

type Persona = NonNullable<Layer6Config["persona"]>;

const PERSONA_HEADERS: Record<Exclude<Persona, "random">, Record<string, string>> = {
  "php-apache":      { "server": "Apache/2.4.57 (Ubuntu)", "x-powered-by": "PHP/8.2.7" },
  "rails-nginx":     { "server": "nginx/1.24.0", "x-powered-by": "Phusion Passenger 6.0.19" },
  "django-gunicorn": { "server": "gunicorn/21.2.0", "x-powered-by": "Django/4.2.10" },
  "asp-net-iis":     { "server": "Microsoft-IIS/10.0", "x-powered-by": "ASP.NET", "x-aspnet-version": "4.0.30319" },
  "wordpress-apache":{ "server": "Apache/2.4.57 (Debian)", "x-powered-by": "PHP/8.1.22", "x-pingback": "/xmlrpc.php" },
  "spring-tomcat":   { "server": "Apache-Coyote/1.1", "x-powered-by": "Spring Boot/3.2.0" },
  "laravel-nginx":   { "server": "nginx/1.24.0", "x-powered-by": "PHP/8.2.7" },
};

const PERSONA_KEYS = Object.keys(PERSONA_HEADERS) as Array<Exclude<Persona, "random">>;

function djb2Hash(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  }
  return h;
}

function resolvePersona(config: Layer6Config, sessionId: string): Exclude<Persona, "random"> {
  if (!config.persona || config.persona === "random") {
    const idx = djb2Hash(sessionId) % PERSONA_KEYS.length;
    return PERSONA_KEYS[idx]!;
  }
  return config.persona;
}

export function buildMimicryHeaders(
  config: Layer6Config,
  sessionId: string
): Record<string, string> {
  if (!config.enabled) return {};
  const persona = resolvePersona(config, sessionId);
  const headers: Record<string, string> = {};

  if (config.spoofServerHeader !== false) {
    headers["server"] = PERSONA_HEADERS[persona]!["server"]!;
  }
  if (config.spoofPoweredBy !== false && PERSONA_HEADERS[persona]!["x-powered-by"]) {
    headers["x-powered-by"] = PERSONA_HEADERS[persona]!["x-powered-by"]!;
  }
  // Copy any additional persona-specific headers
  for (const [k, v] of Object.entries(PERSONA_HEADERS[persona]!)) {
    if (!["server", "x-powered-by"].includes(k)) {
      headers[k] = v;
    }
  }
  return headers;
}

export function applySyntacticMimicry(
  body: string,
  statusCode: number,
  config: Layer6Config,
  sessionId: string
): string {
  if (!config.enabled || config.spoofErrorPages === false) return body;
  if (statusCode < 400) return body;

  const persona = resolvePersona(config, sessionId);

  // Return a persona-appropriate error page
  const errors: Record<Exclude<Persona, "random">, string> = {
    "php-apache": `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>${statusCode} Error</title></head>
<body><h1>${statusCode}</h1><p>The requested URL was not found.</p><hr>
<address>Apache/2.4.57 (Ubuntu) Server at localhost Port 80</address></body></html>`,
    "rails-nginx": `<html><body><h1>${statusCode} Not Found</h1>
<p>No route matches [${statusCode}]</p></body></html>`,
    "django-gunicorn": `<!DOCTYPE html><html><head><title>${statusCode} ${statusCode === 404 ? "Not Found" : "Error"}</title></head>
<body><h1>Not Found</h1><p>The requested resource was not found on this server.</p></body></html>`,
    "asp-net-iis": `<!DOCTYPE html><html><head><title>IIS ${statusCode}</title></head>
<body style="background:white;"><div id="header"><h1>Server Error</h1><h2>HTTP Error ${statusCode}</h2></div></body></html>`,
    "wordpress-apache": `<!DOCTYPE html><html><head><title>Page not found – WordPress</title></head>
<body><div id="page"><p>Nothing was found at this location. Try searching.</p></div></body></html>`,
    "spring-tomcat": `<html><head><title>Apache Tomcat - Error report</title></head>
<body><h1>HTTP Status ${statusCode}</h1><p>The requested resource is not available.</p></body></html>`,
    "laravel-nginx": `<!DOCTYPE html><html><head><title>${statusCode} | Laravel</title></head>
<body><div class="container"><h1>${statusCode}</h1></div></body></html>`,
  };

  return errors[persona] ?? body;
}
