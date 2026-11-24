/* ==========================================================
   Open Shelf — catalog search
   Connects the top-bar search box to GET /api/books?q=<search>.

   • Same-origin, public endpoint: no token or credentials are sent.
   • API data is rendered only with textContent / createElement,
     never innerHTML.
   • Older responses can never overwrite newer results.
   • Works independently of the login code (auth.js is not required).
   ========================================================== */
(function () {
  "use strict";

  const API_PATH = "/api/books";
  const MAX_QUERY_LENGTH = 200;
  const REQUEST_TIMEOUT_MS = 15000;
  const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

  const form = document.querySelector("form.search");
  const input = document.getElementById("search-input");
  const grid = document.getElementById("book-results");
  const section = document.getElementById("featured");
  const heading = document.getElementById("featured-title");
  const subtitle = document.getElementById("featured-subtitle");
  const statusEl = document.getElementById("search-status");
  const errorEl = document.getElementById("search-error");

  // If the page doesn't have the expected elements, leave it untouched.
  if (!form || !input || !grid || !statusEl || !errorEl) return;

  input.maxLength = MAX_QUERY_LENGTH;

  let latestRequestId = 0;
  let activeController = null;

  /* ---------- Messages ---------- */

  function showStatus(text, loading) {
    errorEl.hidden = true;
    errorEl.textContent = "";
    statusEl.textContent = "";
    if (loading) {
      const spinner = document.createElement("span");
      spinner.className = "spinner";
      spinner.setAttribute("aria-hidden", "true");
      statusEl.appendChild(spinner);
    }
    statusEl.appendChild(document.createTextNode(text));
    statusEl.hidden = false;
  }

  function showError(text) {
    statusEl.hidden = true;
    statusEl.textContent = "";
    errorEl.textContent = text;
    errorEl.hidden = false;
  }

  function setBusy(busy) {
    grid.setAttribute("aria-busy", busy ? "true" : "false");
    section.classList.toggle("is-loading", busy);
  }

  /* ---------- Validation ---------- */

  // Returns { ok: true, query } or { ok: false, message }.
  function validate(raw) {
    const query = String(raw || "").replace(/\s+/g, " ").trim();
    if (query.length > MAX_QUERY_LENGTH) {
      return { ok: false, message: "Please shorten your search to " + MAX_QUERY_LENGTH + " characters or fewer." };
    }
    if (CONTROL_CHARS.test(query)) {
      return { ok: false, message: "Your search contains characters that can't be used. Please remove them and try again." };
    }
    return { ok: true, query: query };
  }

  /* ---------- Rendering (safe DOM only) ---------- */

  function asText(value) {
    return value === null || value === undefined ? "" : String(value);
  }

  // Map a genre to one of the existing tag colours.
  function tagClassFor(genre) {
    const g = genre.toLowerCase();
    if (/science/.test(g)) return "science";
    if (/history|biography|memoir/.test(g)) return "history";
    if (/fiction|romance|fantasy|mystery|novel|classic|thriller|poetry|drama/.test(g)) return "fiction";
    return "";
  }

  // Pick a stable fallback cover colour from the book's id or title.
  function toneFor(book) {
    const seed = asText(book.id) + asText(book.title);
    let hash = 0;
    for (let i = 0; i < seed.length; i++) hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
    return hash % 6;
  }

  function buildCover(book, title) {
    const cover = document.createElement("div");
    cover.className = "cover cover-fallback tone-" + toneFor(book);
    cover.setAttribute("aria-hidden", "true");

    const initial = document.createElement("span");
    initial.className = "cover-initial";
    initial.textContent = (title.trim().charAt(0) || "?").toUpperCase();

    const rule = document.createElement("span");
    rule.className = "cover-rule";

    cover.append(initial, rule);
    return cover;
  }

  function buildCard(book) {
    const title = asText(book.title).trim() || "Untitled";
    const author = asText(book.author).trim();
    const genre = asText(book.genre).trim();
    const year = Number(book.publication_year);
    const description = asText(book.description).trim();

    const li = document.createElement("li");
    const article = document.createElement("article");
    article.className = "book-card";

    article.appendChild(buildCover(book, title));

    const h3 = document.createElement("h3");
    h3.textContent = title;
    article.appendChild(h3);

    const authorEl = document.createElement("p");
    authorEl.className = "author";
    authorEl.textContent = author ? "by " + author : "Unknown author";
    article.appendChild(authorEl);

    if (Number.isInteger(year) && year > 0) {
      const meta = document.createElement("p");
      meta.className = "book-meta";
      meta.textContent = "Published " + year;
      article.appendChild(meta);
    }

    if (description) {
      const desc = document.createElement("p");
      desc.className = "book-desc";
      desc.textContent = description;
      article.appendChild(desc);
    }

    if (genre) {
      const tag = document.createElement("span");
      const extra = tagClassFor(genre);
      tag.className = extra ? "tag " + extra : "tag";
      tag.textContent = genre;
      article.appendChild(tag);
    }

    li.appendChild(article);
    return li;
  }

  function renderBooks(books, query) {
    const fragment = document.createDocumentFragment();
    books.forEach((book) => {
      if (book && typeof book === "object") fragment.appendChild(buildCard(book));
    });
    grid.replaceChildren(fragment);

    if (heading) heading.textContent = query ? "Search Results" : "All Books";
    if (subtitle) subtitle.textContent = query ? "Titles and authors" : "The full catalog";

    const count = grid.children.length;
    const noun = count === 1 ? "book" : "books";
    if (count === 0) {
      showStatus(query
        ? "No books match \u201C" + query + "\u201D. Try a different title or author."
        : "The catalog is empty right now.", false);
    } else if (query) {
      showStatus("Showing " + count + " " + noun + " matching \u201C" + query + "\u201D.", false);
    } else {
      showStatus("Showing all " + count + " " + noun + " in the catalog.", false);
    }
  }

  /* ---------- Fetching ---------- */

  async function search(query) {
    const requestId = ++latestRequestId;

    // Cancel the previous request; its result would be stale anyway.
    if (activeController) activeController.abort();
    const controller = new AbortController();
    activeController = controller;

    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, REQUEST_TIMEOUT_MS);

    setBusy(true);
    showStatus(query ? "Searching for \u201C" + query + "\u201D\u2026" : "Loading the catalog\u2026", true);

    const params = new URLSearchParams({ q: query });

    try {
      const response = await fetch(API_PATH + "?" + params.toString(), {
        method: "GET",
        headers: { Accept: "application/json" },
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }

      let data;
      try {
        data = await response.json();
      } catch (e) {
        throw new Error("Invalid JSON");
      }
      if (!data || !Array.isArray(data.books)) {
        throw new Error("Unexpected response shape");
      }

      if (requestId !== latestRequestId) return;   // a newer search has started
      renderBooks(data.books, query);
    } catch (err) {
      if (requestId !== latestRequestId) return;   // superseded: ignore quietly
      if (err && err.name === "AbortError" && !timedOut) return;

      if (timedOut) {
        showError("The search is taking too long. Please try again in a moment.");
      } else if (err instanceof TypeError) {
        showError("We couldn't reach the library. Check your connection and try again.");
      } else {
        showError("Something went wrong while searching. Please try again.");
      }
    } finally {
      clearTimeout(timer);
      if (requestId === latestRequestId) {
        setBusy(false);
        activeController = null;
      }
    }
  }

  /* ---------- Wiring ---------- */

  form.addEventListener("submit", (event) => {
    event.preventDefault();   // no page reload

    const result = validate(input.value);
    if (!result.ok) {
      // Cancel any search still in flight so it can't replace this message.
      latestRequestId++;
      if (activeController) activeController.abort();
      setBusy(false);
      showError(result.message);
      input.focus();
      return;
    }

    search(result.query);
    section.scrollIntoView({ block: "start" });
  });
})();