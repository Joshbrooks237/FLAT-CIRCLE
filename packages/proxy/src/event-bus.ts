/**
 * EventBus — routes FlatCircleEvents to all subscribers including
 * dashboard WebSocket connections, alerting webhooks, and external listeners.
 */

import type { FlatCircleEvent, EventEmitterFn, AlertingConfig } from "@flat-circle/core/types";

export class EventBus {
  private readonly subscribers = new Set<EventEmitterFn>();
  private readonly alerting: AlertingConfig | undefined;

  constructor(alerting?: AlertingConfig) {
    this.alerting = alerting;
  }

  emit(event: FlatCircleEvent): void {
    for (const sub of this.subscribers) {
      try { sub(event); } catch { /* individual subscriber errors are isolated */ }
    }
    void this.dispatchAlerts(event);
  }

  subscribe(handler: EventEmitterFn): () => void {
    this.subscribers.add(handler);
    return () => this.subscribers.delete(handler);
  }

  private async dispatchAlerts(event: FlatCircleEvent): Promise<void> {
    if (!this.alerting) return;

    const highPriority =
      event.type === "canary.fired" ||
      event.type === "merkle.tamper.detected" ||
      event.type === "campaign.matched" ||
      (event.type === "threat.classified" && event.threatClass === "nation-state");

    if (!highPriority) return;

    const payload = JSON.stringify({
      text: `*Flat Circle Alert* — \`${event.type}\`\nSession: ${event.sessionId}\nIP: ${event.ip}\nTier: ${event.providerTier}`,
      event,
    });

    const endpoints: Array<{ url: string; headers?: Record<string, string> }> = [];

    if (this.alerting.slack) {
      endpoints.push({ url: this.alerting.slack });
    }
    if (this.alerting.discord) {
      endpoints.push({ url: this.alerting.discord });
    }
    if (this.alerting.webhook) {
      endpoints.push({
        url: this.alerting.webhook.url,
        headers: this.alerting.webhook.secret
          ? { "x-flat-circle-signature": this.alerting.webhook.secret }
          : undefined,
      });
    }

    await Promise.allSettled(
      endpoints.map(({ url, headers }) =>
        fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...headers },
          body: payload,
          signal: AbortSignal.timeout(5_000),
        })
      )
    );
  }
}
