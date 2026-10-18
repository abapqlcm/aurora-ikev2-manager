// CSP-compatible confirmation dialogs. Pages mark a form with data-confirm="...".
// This is a UX guard only: the server independently validates every destructive
// action (e.g. the typed username must match before a user is deleted).
document.addEventListener("submit", function (event) {
  var message = event.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
