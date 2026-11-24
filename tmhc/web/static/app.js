/* Live progress for every page: reports keep building on the server whatever page is open. */
(function () {
  "use strict";
  var panel = document.getElementById("activity");
  var btn = document.getElementById("act-btn");
  var label = document.getElementById("act-label");
  var seenActive = {};          // keys that were building/queued on the previous poll
  var minimized = false;
  try { minimized = sessionStorage.getItem("tmhc-min") === "1"; } catch (e) {}

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
    });
  }

  function toast(r) {
    var key = "tmhc-toast-" + r.key + "-" + r.status;
    try { if (sessionStorage.getItem(key)) return; sessionStorage.setItem(key, "1"); } catch (e) {}
    var t = document.createElement("a");
    t.className = "toast " + r.status;
    t.href = r.url;
    t.innerHTML = r.status === "done"
      ? "<b>Report ready</b><br>" + esc(r.client) + " &middot; " + esc(r.short) + " " + esc(r.quarter) + " &ndash; open to download"
      : "<b>Build stopped</b><br>" + esc(r.client) + " &middot; " + esc(r.short) + " " + esc(r.quarter) + " &ndash; open for details";
    panel.appendChild(t);
    setTimeout(function () { t.remove(); }, 12000);
  }

  function drawPanel(active) {
    var box = panel.querySelector(".apanel");
    if (!active.length) { if (box) box.remove(); return; }
    if (!box) {
      box = document.createElement("div");
      box.className = "apanel" + (minimized ? " min" : "");
      panel.insertBefore(box, panel.firstChild);
    }
    var html = '<div class="ah" onclick="TMHC.togglePanel()"><span>Generating<span class="n">' + active.length +
      '</span></span><span>' + (minimized ? "&#9650;" : "&#9660;") + '</span></div><div class="items">';
    active.forEach(function (j) {
      var pct = j.status === "building" ? j.pct + "%" : "queued";
      html += '<a class="aitem" href="' + esc(j.url) + '"><div class="t"><span>' + esc(j.client) + '</span><span>' +
        esc(j.short) + " " + esc(j.quarter) + " &middot; " + pct + '</span></div>' +
        '<div class="bar ' + esc(j.status) + '"><i style="width:' + (j.pct || 0) + '%"></i></div>' +
        '<div class="d">' + esc(j.detail) + '</div></a>';
    });
    box.innerHTML = html + "</div>";
  }

  function updateRows(active) {
    var byKey = {};
    active.forEach(function (j) { byKey[j.key] = j; });
    document.querySelectorAll(".live[data-key]").forEach(function (el) {
      var j = byKey[el.dataset.key];
      var was = el.dataset.status;
      if (j) {
        var bar = el.querySelector(".bar");
        if (bar) {
          bar.className = "bar " + j.status;
          bar.querySelector("i").style.width = (j.pct || 0) + "%";
          var lbl = el.querySelector(".lbl");
          if (lbl) lbl.textContent = j.status + (j.status === "building" ? " · " + j.pct + "%" : "");
          var d = el.querySelector(".live-detail");
          if (d) d.textContent = j.detail;
        } else if (was !== j.status) {
          location.reload();             // a report on this page started building
        }
        el.dataset.status = j.status;
      } else if (was === "building" || was === "queued") {
        location.reload();               // finished - show the downloads
      }
    });
    var s = document.getElementById("stat-active");
    if (s) s.textContent = active.length;
  }

  var timer = null;
  function poll() {
    fetch("/api/activity", {credentials: "same-origin", cache: "no-store"}).then(function (r) {
      if (r.status === 401) { location.href = "/login"; return null; }
      return r.json();
    }).then(function (data) {
      if (!data) return;
      var active = data.active || [];
      if (btn) {
        btn.classList.toggle("busy", active.length > 0);
        label.textContent = active.length ? active.length + " report" + (active.length > 1 ? "s" : "") + " generating"
          : "No reports building";
      }
      drawPanel(active);
      updateRows(active);
      (data.recent || []).forEach(toast);           // finished in the last 2 minutes (once per tab)
      seenActive = {};
      active.forEach(function (j) { seenActive[j.key] = 1; });
      timer = setTimeout(poll, active.length ? 2000 : 8000);
    }).catch(function () { timer = setTimeout(poll, 10000); });
  }

  /* report page: big progress card */
  function pollJob() {
    var card = document.getElementById("job-progress");
    if (!card) return;
    var steps = card.querySelectorAll("#jp-steps span");
    function draw(st) {
      card.hidden = !(st.status === "building" || st.status === "queued");
      document.getElementById("jp-pct").textContent = (st.status === "queued" ? 0 : st.pct) + "%";
      document.getElementById("jp-title").textContent = st.status === "building" ? "Generating the report" : "Queued – starting";
      var bar = document.getElementById("jp-bar");
      bar.className = "bar big " + st.status;
      bar.querySelector("i").style.width = (st.pct || 0) + "%";
      document.getElementById("jp-detail").textContent = st.detail;
      for (var i = 0; i < steps.length; i++) {
        var at = +steps[i].dataset.at, next = i + 1 < steps.length ? +steps[i + 1].dataset.at : 101;
        steps[i].className = st.pct >= next ? "done" : (st.pct >= at && st.status === "building" ? "now" : "");
      }
    }
    function tick() {
      fetch(card.dataset.api, {credentials: "same-origin", cache: "no-store"}).then(function (r) { return r.json(); })
        .then(function (st) {
          var was = card.dataset.status;
          card.dataset.status = st.status;
          if ((was === "building" || was === "queued") && (st.status === "done" || st.status === "error")) {
            location.reload();
            return;
          }
          draw(st);
          setTimeout(tick, (st.status === "building" || st.status === "queued") ? 1500 : 6000);
        }).catch(function () { setTimeout(tick, 8000); });
    }
    if (card.dataset.status === "building" || card.dataset.status === "queued") {
      draw({status: card.dataset.status, pct: parseInt(document.getElementById("jp-pct").textContent) || 0,
            detail: document.getElementById("jp-detail").textContent});
    }
    tick();
  }

  /* uploads with a progress bar; the report itself is generated on the server afterwards */
  function wireUploads() {
    document.querySelectorAll("form[data-upload]").forEach(function (form) {
      form.addEventListener("submit", function (ev) {
        if (!window.XMLHttpRequest || !window.FormData) return;     // plain form post
        if (form.checkValidity && !form.checkValidity()) return;
        ev.preventDefault();
        var box = form.querySelector(".upl");
        var bar = box ? box.querySelector(".bar i") : null;
        var pctEl = box ? box.querySelector("[data-pct]") : null;
        var button = form.querySelector("button");
        if (button) { button.disabled = true; button.dataset.txt = button.textContent; button.textContent = "Uploading..."; }
        if (box) box.classList.add("on");
        var xhr = new XMLHttpRequest();
        xhr.open("POST", form.action);
        xhr.upload.onprogress = function (e) {
          if (!e.lengthComputable) return;
          var p = Math.round(100 * e.loaded / e.total);
          if (bar) bar.style.width = p + "%";
          if (pctEl) pctEl.textContent = p + "%";
          if (p >= 100 && button) button.textContent = "Starting...";
        };
        xhr.onload = function () {
          var url = xhr.responseURL || "";
          if (xhr.status === 200 && url && url.indexOf(form.action) === -1) { location.href = url; return; }
          // the form came back with a message (missing build, duplicate report...)
          document.open(); document.write(xhr.responseText); document.close();
        };
        xhr.onerror = function () {
          if (button) { button.disabled = false; button.textContent = button.dataset.txt; }
          alert("Upload failed - check the connection to the server and try again.");
        };
        xhr.send(new FormData(form));
      });
    });
    document.querySelectorAll(".drop").forEach(function (d) {
      d.addEventListener("dragover", function () { d.classList.add("over"); });
      d.addEventListener("dragleave", function () { d.classList.remove("over"); });
      d.addEventListener("drop", function () { d.classList.remove("over"); });
    });
  }

  window.TMHC = {
    togglePanel: function () {
      minimized = !minimized;
      try { sessionStorage.setItem("tmhc-min", minimized ? "1" : "0"); } catch (e) {}
      var box = panel.querySelector(".apanel");
      if (box) box.classList.toggle("min", minimized);
    },
    filterClients: function (q) {
      q = (q || "").toLowerCase();
      document.querySelectorAll("#cgrid .ccard").forEach(function (c) {
        c.style.display = c.dataset.name.indexOf(q) === -1 ? "none" : "";
      });
    }
  };

  wireUploads();
  pollJob();
  poll();
})();
