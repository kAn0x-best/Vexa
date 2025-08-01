document.getElementById("message-input").addEventListener("keydown", e => {
    if (e.key === "Enter") document.getElementById("send-btn").click();
});
