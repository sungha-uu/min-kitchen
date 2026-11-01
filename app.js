// 급식 레시피 노트 — 암호화된 vault/ 데이터를 비밀번호로 풀어 화면에 그린다.
const TYPE_ORDER = ["국물·면", "메인·반찬", "식사·간식", "소스·양념", "기타"];
const SCALE_PRESETS = [0.5, 1, 2, 5, 10];
const KEY_STORE = "srn-key";
const THEME_STORE = "srn-theme";

const $ = (selector) => document.querySelector(selector);
const listEl = $("#recipeList");
const detailEl = $("#recipeDetail");
const narrow = window.matchMedia("(max-width:820px)");

const state = { type: "all", query: "", selected: null, multiplier: 1, tab: "recipe", checked: new Set() };
let recipes = [];
let vault = null; // { key: CryptoKey, salt: string }
const imageCache = new Map();

const ICON = {
  check: '<svg viewBox="0 0 12 12"><path d="M2.5 6.2 5 8.5l4.5-5"/></svg>',
  link: '<svg viewBox="0 0 24 24"><path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1"/></svg>',
  print: '<svg viewBox="0 0 24 24"><path d="M7 9V4h10v5"/><rect x="4" y="9" width="16" height="8" rx="2"/><path d="M7 14h10v6H7z"/></svg>',
  back: '<svg viewBox="0 0 24 24"><path d="M15 5l-7 7 7 7"/></svg>',
  expand: '<svg viewBox="0 0 24 24"><path d="M14 4h6v6M10 20H4v-6M20 4l-7 7M4 20l7-7"/></svg>',
  sun: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 3v1.5M12 19.5V21M3 12h1.5M19.5 12H21M5.6 5.6l1.1 1.1M17.3 17.3l1.1 1.1M5.6 18.4l1.1-1.1M17.3 6.7l1.1-1.1"/></svg>',
  moon: '<svg viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z"/></svg>',
};

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const normalize = (value) => String(value ?? "").toLowerCase().replace(/\s+/g, "");
const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const bytesToB64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));

/* ---------- 암호 해제 ---------- */
function storage(remember) {
  return remember ? localStorage : sessionStorage;
}
function readStoredKey() {
  for (const store of [sessionStorage, localStorage]) {
    try {
      const saved = JSON.parse(store.getItem(KEY_STORE));
      if (saved?.key && saved?.salt) return saved;
    } catch {}
  }
  return null;
}
function clearStoredKey() {
  for (const store of [sessionStorage, localStorage]) {
    try { store.removeItem(KEY_STORE); } catch {}
  }
}
async function fetchMeta() {
  const res = await fetch("vault/meta.json", { cache: "no-store" });
  if (!res.ok) throw new Error("meta");
  return res.json();
}
async function deriveRawKey(password, meta) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: b64ToBytes(meta.salt), iterations: meta.iterations }, base, 256);
}
async function decryptBuffer(buffer, key) {
  const bytes = new Uint8Array(buffer);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12));
}
async function openVault(rawKey, salt) {
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
  const res = await fetch(`vault/data.bin?s=${encodeURIComponent(salt.slice(0, 8))}`);
  if (!res.ok) throw new Error("data");
  const plain = await decryptBuffer(await res.arrayBuffer(), key); // 비밀번호가 틀리면 여기서 실패한다
  vault = { key, salt };
  return JSON.parse(new TextDecoder().decode(plain));
}
async function loadImage(recipe) {
  if (!recipe.image) return null;
  if (!imageCache.has(recipe.id)) {
    const job = fetch(`vault/img/${recipe.image.file}?s=${encodeURIComponent(vault.salt.slice(0, 8))}`)
      .then((res) => (res.ok ? res.arrayBuffer() : Promise.reject(new Error("image"))))
      .then((buffer) => decryptBuffer(buffer, vault.key))
      .then((plain) => URL.createObjectURL(new Blob([plain], { type: recipe.image.type })));
    job.catch(() => imageCache.delete(recipe.id));
    imageCache.set(recipe.id, job);
  }
  return imageCache.get(recipe.id);
}

async function unlockWithPassword(password, remember) {
  const meta = await fetchMeta();
  const raw = await deriveRawKey(password, meta);
  const data = await openVault(raw, meta.salt);
  try { storage(remember).setItem(KEY_STORE, JSON.stringify({ key: bytesToB64(raw), salt: meta.salt })); } catch {}
  return data;
}
async function unlockFromStorage() {
  const saved = readStoredKey();
  if (!saved) return null;
  try {
    const meta = await fetchMeta();
    if (meta.salt !== saved.salt) throw new Error("stale"); // 비밀번호가 바뀌면 다시 입력받는다
    return await openVault(b64ToBytes(saved.key), saved.salt);
  } catch {
    clearStoredKey();
    return null;
  }
}

function showLock(message = "") {
  $("#app").hidden = true;
  $("#lock").hidden = false;
  $("#lockError").textContent = message;
  setTimeout(() => $("#pinInput").focus(), 50);
}
function start(data) {
  recipes = data;
  recipes.forEach((item, index) => {
    const names = (item.ingredients || []).flatMap((group) => group.items.map((row) => row[0]));
    item._search = normalize([item.name, item.type, ...names].join(" "));
    item._ingredientCount = names.length;
    item._order = index;
  });
  recipes.sort((a, b) => a.name.localeCompare(b.name, "ko"));
  $("#lock").hidden = true;
  $("#app").hidden = false;
  renderCategories();
  fromHash();
}

$("#lockForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#pinInput");
  const button = $("#unlockButton");
  if (!input.value) return;
  button.disabled = true;
  button.textContent = "여는 중…";
  $("#lockError").textContent = "";
  try {
    start(await unlockWithPassword(input.value, $("#rememberInput").checked));
  } catch (err) {
    const card = $("#lockForm");
    card.classList.remove("shake");
    void card.offsetWidth;
    card.classList.add("shake");
    $("#lockError").textContent = err?.name === "OperationError" ? "비밀번호가 맞지 않아요." : "데이터를 불러오지 못했어요. 잠시 후 다시 시도해 주세요.";
    input.select();
  } finally {
    button.disabled = false;
    button.textContent = "열기";
  }
});
$("#lockButton").addEventListener("click", () => {
  clearStoredKey();
  location.hash = "";
  location.reload();
});

/* ---------- 테마 ---------- */
function currentTheme() {
  return document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}
function renderThemeButton() {
  $("#themeButton").innerHTML = currentTheme() === "dark" ? ICON.sun : ICON.moon;
}
$("#themeButton").addEventListener("click", () => {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_STORE, next); } catch {}
  renderThemeButton();
});
renderThemeButton();

/* ---------- 목록 ---------- */
function filtered() {
  const q = normalize(state.query);
  return recipes.filter((item) => (state.type === "all" || item.type === state.type) && (!q || item._search.includes(q)));
}
function highlight(text) {
  const q = state.query.trim();
  if (!q) return escapeHtml(text);
  const index = text.toLowerCase().indexOf(q.toLowerCase());
  if (index < 0) return escapeHtml(text);
  return `${escapeHtml(text.slice(0, index))}<mark>${escapeHtml(text.slice(index, index + q.length))}</mark>${escapeHtml(text.slice(index + q.length))}`;
}
function matchedIngredient(item) {
  const q = normalize(state.query);
  if (!q || normalize(item.name).includes(q)) return "";
  for (const group of item.ingredients || []) for (const [name] of group.items) if (normalize(name).includes(q)) return name;
  return "";
}

function renderCategories() {
  const counts = recipes.reduce((acc, item) => ((acc[item.type] = (acc[item.type] || 0) + 1), acc), {});
  const types = [["all", "전체", recipes.length], ...TYPE_ORDER.filter((t) => counts[t]).map((t) => [t, t, counts[t]])];
  $("#categoryList").innerHTML = types
    .map(([id, label, count]) => `<button class="cat${state.type === id ? " is-active" : ""}" data-type="${escapeHtml(id)}" aria-pressed="${state.type === id}">${escapeHtml(label)}<small>${count}</small></button>`)
    .join("");
}
function renderList() {
  const items = filtered();
  $("#filterTitle").textContent = state.type === "all" ? "전체 레시피" : state.type;
  $("#visibleCount").textContent = `${items.length}개`;
  $("#emptyState").hidden = items.length > 0;
  listEl.innerHTML = items
    .map((item) => {
      const hit = matchedIngredient(item);
      const sub = hit ? `재료 · ${highlight(hit)}` : escapeHtml([item.type, item.yield].filter(Boolean).join(" · "));
      return `<li><button class="item${item.id === state.selected ? " is-active" : ""}" data-id="${item.id}"><b>${highlight(item.name)}</b><small>${sub}</small></button></li>`;
    })
    .join("");
}

/* ---------- 상세 ---------- */
function formatAmount(value, multiplier) {
  if (value === null || value === undefined || value === "") return { text: "—", numeric: false };
  const numeric = typeof value === "number" || (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value)));
  if (!numeric) return { text: String(value), numeric: false };
  return { text: (Number(value) * multiplier).toLocaleString("ko-KR", { maximumFractionDigits: 2 }), numeric: true };
}

function renderWelcome() {
  detailEl.innerHTML = `<div class="welcome"><h1>무엇을 만들어 볼까요?</h1><p>왼쪽에서 메뉴를 고르거나 재료로 검색해 보세요.</p></div>`;
}

function renderDetail() {
  const item = recipes.find((r) => r.id === state.selected);
  if (!item) return renderWelcome();
  const list = filtered();
  const pos = list.findIndex((r) => r.id === item.id);
  const prev = pos > 0 ? list[pos - 1] : null;
  const next = pos >= 0 && pos < list.length - 1 ? list[pos + 1] : null;

  const facts = [["분량", item.yield], ["준비", item.prep], ["조리", item.cook]]
    .filter(([, v]) => v)
    .map(([k, v]) => `<div><dt>${k}</dt><dd>${escapeHtml(v)}</dd></div>`)
    .join("");

  const isPreset = SCALE_PRESETS.includes(state.multiplier);
  const scaler = `<div class="scaler" role="group" aria-label="재료 배수">${SCALE_PRESETS.map((m) => `<button data-scale="${m}" class="${state.multiplier === m ? "is-active" : ""}">×${m}</button>`).join("")}<input id="scaleInput" class="${isPreset ? "" : "is-active"}" type="number" min="0.1" step="0.1" inputmode="decimal" aria-label="배수 직접 입력" placeholder="직접" value="${isPreset ? "" : state.multiplier}"></div>`;

  const groups = (item.ingredients || [])
    .map((group, gi) => `<div class="group">${(item.ingredients.length > 1 || group.group !== "재료") ? `<h3>${escapeHtml(group.group)}</h3>` : ""}<ul>${group.items
      .map(([name, value, unit], ri) => {
        const key = `${gi}-${ri}`;
        const amount = formatAmount(value, state.multiplier);
        return `<li class="ing${state.checked.has(key) ? " is-checked" : ""}" data-check="${key}" role="checkbox" aria-checked="${state.checked.has(key)}" tabindex="0"><span class="box">${ICON.check}</span><span class="name">${escapeHtml(name)}</span><span class="amt${amount.numeric ? "" : " text"}">${escapeHtml(amount.text)}${amount.numeric && unit ? `<small>${escapeHtml(unit)}</small>` : ""}</span></li>`;
      })
      .join("")}</ul></div>`)
    .join("");

  const steps = item.steps || [];
  let counter = 0;
  const phases = [["prep", "준비"], ["cook", "조리"]]
    .map(([phase, label]) => [phase, label, steps.filter((s) => (s.phase === "prep" ? "prep" : "cook") === phase)])
    .filter(([, , rows]) => rows.length);
  const showPhaseLabels = phases.length > 1;
  const method = phases
    .map(([phase, label, rows]) => `<div class="phase ${phase}">${showPhaseLabels ? `<h3><span>${label}</span></h3>` : ""}<ol class="steps">${rows
      .map((s) => `<li><span class="num">${++counter}</span><p>${escapeHtml(s.body)}${s.tip ? `<span class="tip"><b>TIP</b>${escapeHtml(s.tip)}</span>` : ""}</p></li>`)
      .join("")}</ol></div>`)
    .join("");

  detailEl.dataset.tab = state.tab;
  detailEl.innerHTML = `
    <div class="detail-top">
      <button class="ghost back" data-back>${ICON.back}목록</button>
      <div class="crumbs"><span>급식 레시피</span><i></i><span>${escapeHtml(item.type)}</span></div>
      <div class="top-actions">
        <button class="ghost" data-copy>${ICON.link}<span>링크 복사</span></button>
        <button class="ghost print" data-print>${ICON.print}<span>인쇄</span></button>
      </div>
    </div>
    <div class="detail-grid">
      <div class="recipe-body">
        <h1 class="title">${escapeHtml(item.name)}</h1>
        ${facts ? `<dl class="facts">${facts}</dl>` : ""}
        ${item.image ? `<div class="tabs" role="tablist"><button role="tab" data-tab="recipe" class="${state.tab === "recipe" ? "is-active" : ""}">레시피</button><button role="tab" data-tab="original" class="${state.tab === "original" ? "is-active" : ""}">원본 이미지</button></div>` : ""}
        <div class="recipe-content">
          <section class="block">
            <div class="block-head"><h2>재료<small>${item._ingredientCount}가지</small></h2>${scaler}</div>
            <div class="groups${(item.ingredients || []).length === 1 ? " single" : ""}">${groups}</div>
          </section>
          ${method ? `<section class="block"><div class="block-head"><h2>만드는 법<small>${counter}단계</small></h2></div>${method}</section>` : ""}
          ${item.note ? `<div class="note">${escapeHtml(item.note)}</div>` : ""}
        </div>
      </div>
      ${item.image ? `<aside class="original" aria-label="원본 레시피 이미지">
        <div class="original-card">
          <div class="original-head"><div><b>원본 레시피</b><small>눌러서 크게 보기</small></div><button class="icon-btn" data-zoom aria-label="원본 크게 보기">${ICON.expand}</button></div>
          <button class="original-frame" data-zoom aria-label="${escapeHtml(item.name)} 원본 크게 보기"><div class="loading skeleton">원본 불러오는 중…</div></button>
        </div>
      </aside>` : ""}
    </div>
    <nav class="pager" aria-label="이전 다음 레시피">
      ${prev ? `<button data-id="${prev.id}"><small>← 이전</small><b>${escapeHtml(prev.name)}</b></button>` : `<span class="spacer"></span>`}
      ${next ? `<button data-id="${next.id}"><small>다음 →</small><b>${escapeHtml(next.name)}</b></button>` : `<span class="spacer"></span>`}
    </nav>`;

  if (item.image) {
    loadImage(item)
      .then((url) => {
        const frame = detailEl.querySelector(".original-frame");
        if (!frame || state.selected !== item.id) return;
        frame.innerHTML = `<img src="${url}" alt="${escapeHtml(item.name)} 원본 레시피">`;
      })
      .catch(() => {
        const loading = detailEl.querySelector(".original-frame .loading");
        if (loading) { loading.classList.remove("skeleton"); loading.textContent = "원본 이미지를 불러오지 못했어요."; }
      });
  }
}

function select(id, { push = true } = {}) {
  if (state.selected !== id) {
    state.checked.clear();
    state.tab = "recipe";
  }
  state.selected = id;
  document.body.classList.toggle("reading", Boolean(id) && narrow.matches);
  if (push) history.pushState(null, "", id ? `#${id}` : location.pathname);
  renderList();
  renderDetail();
  if (id) {
    window.scrollTo(0, 0);
    $("#main").scrollTop = 0;
    listEl.querySelector(".is-active")?.scrollIntoView({ block: "nearest" });
  }
}

function fromHash() {
  const id = decodeURIComponent(location.hash.slice(1));
  if (recipes.some((r) => r.id === id)) return select(id, { push: false });
  document.body.classList.remove("reading");
  state.selected = narrow.matches ? null : state.selected || filtered()[0]?.id || null;
  renderList();
  renderDetail();
}

/* ---------- 이미지 뷰어 ---------- */
const viewer = $("#viewer");
async function openViewer() {
  const item = recipes.find((r) => r.id === state.selected);
  if (!item?.image) return;
  $("#viewerTitle").textContent = `${item.name} · 원본`;
  viewer.classList.remove("is-zoomed");
  $("#viewerZoom").textContent = "원래 크기";
  $("#viewerImage").removeAttribute("src");
  viewer.hidden = false;
  document.body.style.overflow = "hidden";
  try { $("#viewerImage").src = await loadImage(item); } catch {}
}
function closeViewer() {
  viewer.hidden = true;
  document.body.style.overflow = "";
}
function toggleZoom() {
  const zoomed = viewer.classList.toggle("is-zoomed");
  $("#viewerZoom").textContent = zoomed ? "화면에 맞추기" : "원래 크기";
}
$("#viewerClose").addEventListener("click", closeViewer);
$("#viewerZoom").addEventListener("click", toggleZoom);
$("#viewerImage").addEventListener("click", toggleZoom);
viewer.addEventListener("click", (e) => { if (e.target === viewer || e.target.id === "viewerStage") closeViewer(); });

/* ---------- 이벤트 ---------- */
$("#categoryList").addEventListener("click", (e) => {
  const chip = e.target.closest("[data-type]");
  if (!chip) return;
  state.type = chip.dataset.type;
  renderCategories();
  renderList();
});
$("#searchInput").addEventListener("input", (e) => {
  state.query = e.target.value;
  renderList();
});
$("#searchInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const first = filtered()[0];
    if (first) select(first.id);
  }
});
listEl.addEventListener("click", (e) => {
  const button = e.target.closest("[data-id]");
  if (button) select(button.dataset.id);
});
document.querySelector("[data-home]").addEventListener("click", (e) => {
  e.preventDefault();
  state.type = "all";
  state.query = "";
  $("#searchInput").value = "";
  renderCategories();
  select(narrow.matches ? null : recipes[0]?.id || null);
});

function toggleCheck(row) {
  const key = row.dataset.check;
  state.checked.has(key) ? state.checked.delete(key) : state.checked.add(key);
  row.classList.toggle("is-checked", state.checked.has(key));
  row.setAttribute("aria-checked", state.checked.has(key));
}
detailEl.addEventListener("click", (e) => {
  const target = e.target;
  const scale = target.closest("[data-scale]");
  if (scale) {
    state.multiplier = Number(scale.dataset.scale);
    return renderDetail();
  }
  const row = target.closest("[data-check]");
  if (row) return toggleCheck(row);
  const tab = target.closest(".tabs [data-tab]");
  if (tab) {
    state.tab = tab.dataset.tab;
    detailEl.dataset.tab = state.tab;
    detailEl.querySelectorAll(".tabs [data-tab]").forEach((b) => b.classList.toggle("is-active", b === tab));
    return;
  }
  const go = target.closest(".pager [data-id]");
  if (go) return select(go.dataset.id);
  if (target.closest("[data-zoom]")) return openViewer();
  if (target.closest("[data-back]")) return location.hash ? history.back() : select(null);
  if (target.closest("[data-print]")) return window.print();
  const copy = target.closest("[data-copy]");
  if (copy) {
    navigator.clipboard?.writeText(location.href).then(() => {
      const label = copy.querySelector("span");
      label.textContent = "복사됨";
      setTimeout(() => (label.textContent = "링크 복사"), 1400);
    });
  }
});
detailEl.addEventListener("keydown", (e) => {
  const row = e.target.closest("[data-check]");
  if (row && (e.key === " " || e.key === "Enter")) {
    e.preventDefault();
    toggleCheck(row);
  }
});
detailEl.addEventListener("change", (e) => {
  if (e.target.id !== "scaleInput") return;
  const value = Number(e.target.value);
  if (value > 0) {
    state.multiplier = value;
    renderDetail();
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !viewer.hidden) return closeViewer();
  if (e.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName) && !$("#app").hidden) {
    e.preventDefault();
    if (narrow.matches && document.body.classList.contains("reading")) select(null);
    $("#searchInput").focus();
  }
});
window.addEventListener("popstate", () => recipes.length && fromHash());
narrow.addEventListener("change", () => recipes.length && fromHash());

/* ---------- 시작 ---------- */
(async () => {
  if (!window.crypto?.subtle) return showLock("이 브라우저에서는 열 수 없어요. 최신 브라우저로 접속해 주세요.");
  const data = await unlockFromStorage();
  data ? start(data) : showLock();
})();
