import { html, LitElement } from "lit";
import { AssistantMessage } from "@pi-components/components/Messages.js";

class MessageFeedback extends LitElement {
  static properties = { records: {}, sessionId: {}, messageIndex: {}, editing: { state: true } };
  createRenderRoot() { return this; }
  render() {
    return html`<div class="message-feedback">
      ${(this.records || []).filter(record => record.messageIndex === this.messageIndex).map(record =>
        html`<p class="feedback-note">${record.text}</p>`)}
      <button class="link" aria-expanded=${!!this.editing} @click=${() => { this.editing = !this.editing; }}>Feedback</button>
      ${this.editing ? html`<form @submit=${event => {
        event.preventDefault();
        const text = this.querySelector("input").value.trim();
        if (!text) return;
        this.dispatchEvent(new CustomEvent("message-feedback", { bubbles: true, detail: {
          sessionId: this.sessionId, messageIndex: this.messageIndex, text,
        } }));
        this.editing = false;
      }}><input aria-label="Message feedback" placeholder="Your feedback" required><button class="secondary" type="submit">Save</button></form>` : ""}
    </div>`;
  }
  updated() { if (this.editing) this.querySelector("input").focus(); }
}
customElements.define("message-feedback", MessageFeedback);

export function installMessageFeedback(context) {
  const render = AssistantMessage.prototype.render;
  AssistantMessage.prototype.render = function () {
    const { session, messages } = context();
    const messageIndex = messages.indexOf(this.message);
    return html`${render.call(this)}${messageIndex < 0 ? "" : html`<message-feedback
      .sessionId=${session.id} .messageIndex=${messageIndex} .records=${session.feedback || []}
    ></message-feedback>`}`;
  };
}
