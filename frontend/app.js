// ---------------------------------------------------------------------------
// Prompt-injection lab — chat widget
// Talks to the backend POST /chat. Keeps history client-side and sends the
// whole conversation each turn. Set BACKEND_URL if your backend is elsewhere.
// ---------------------------------------------------------------------------
const BACKEND_URL = "http://localhost:8000";

const el = (id) => document.getElementById(id);
const panel = el("chatPanel");
const fab = el("chatToggle");
const messagesEl = el("messages");
const form = el("chatForm");
const textInput = el("chatText");
const levelSelect = el("levelSelect");
const winBanner = el("winBanner");

let history = [];          // [{role:'user'|'assistant', content:'...'}]
let sending = false;

const GREETING = "Hi! I'm HelpBot, the Acme Learn support assistant. Ask me about password resets, billing, or course access.";

// ---- panel open / close ----------------------------------------------------
function openPanel() {
  panel.hidden = false;
  fab.hidden = true;
  if (messagesEl.childElementCount === 0) addMessage("bot", GREETING);
  textInput.focus();
}
function closePanel() {
  panel.hidden = true;
  fab.hidden = false;
}
fab.addEventListener("click", openPanel);
el("chatClose").addEventListener("click", closePanel);

el("chatReset").addEventListener("click", () => {
  history = [];
  messagesEl.innerHTML = "";
  winBanner.hidden = true;
  addMessage("bot", GREETING);
  textInput.focus();
});

// ---- rendering -------------------------------------------------------------
function addMessage(who, text, meta) {
  const row = document.createElement("div");
  row.className = "msg msg--" + (who === "user" ? "user" : "bot");

  const bubble = document.createElement("div");
  bubble.className = "msg__bubble";
  bubble.textContent = text;
  row.appendChild(bubble);

  if (meta) {
    const m = document.createElement("div");
    m.className = "msg__meta" + (meta.leak ? " msg__meta--leak" : "");
    m.textContent = meta.text;
    bubble.appendChild(document.createElement("br"));
    bubble.appendChild(m);
  }

  messagesEl.appendChild(row);
  messagesEl.scrollTop = messagesEl.scrollHeight;
  return row;
}

function showTyping() {
  const row = document.createElement("div");
  row.className = "msg msg--bot typing";
  row.id = "typingRow";
  row.innerHTML = '<div class="msg__bubble">HelpBot is typing…</div>';
  messagesEl.appendChild(row);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}
function hideTyping() {
  const t = el("typingRow");
  if (t) t.remove();
}

// ---- sending ---------------------------------------------------------------
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = textInput.value.trim();
  if (!text || sending) return;

  addMessage("user", text);
  history.push({ role: "user", content: text });
  textInput.value = "";
  sending = true;
  showTyping();

  try {
    const res = await fetch(BACKEND_URL + "/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: history, level: Number(levelSelect.value) }),
    });
    const data = await res.json();
    hideTyping();

    const reply = data.reply ?? "[no reply]";
    history.push({ role: "assistant", content: reply });

    let meta;
    const triggered = data.guardrails_triggered || [];
    if (data.secret_leaked) {
      meta = { text: "secret leaked", leak: true };
      winBanner.hidden = false;
    } else if (triggered.length) {
      meta = { text: "blocked by: " + triggered.join(", ") + "  (level " + data.level + ")" };
    }
    addMessage("bot", reply, meta);
  } catch (err) {
    hideTyping();
    addMessage("bot", "Couldn't reach the backend at " + BACKEND_URL +
      ". Is it running? (" + err.message + ")");
  } finally {
    sending = false;
    textInput.focus();
  }
});

// Reset the win banner when the level changes (fresh challenge per level).
levelSelect.addEventListener("change", () => { winBanner.hidden = true; });
