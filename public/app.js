fetch("/api/me", { credentials: "same-origin" })
  .then((response) => (response.ok ? response.json() : null))
  .then((user) => {
    const status = document.getElementById("status");
    status.textContent = user
      ? `Sessão de ${user.email ?? user.displayName}.`
      : "Nenhuma sessão neste navegador.";
  });
