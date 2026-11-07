
const chatForm = document.getElementById("chat-form");
const chatBox = document.getElementById("chat-box");
const userInput = document.getElementById("user-input");

function addMessage(message, type) {
    const messageDiv = document.createElement("div");

    messageDiv.className = `message ${type}`;

    // Intentionally unsafe rendering for the local security lab.
    messageDiv.innerHTML = message;

    chatBox.appendChild(messageDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
}

chatForm.addEventListener("submit", async function(event) {

    event.preventDefault();

    const message = userInput.value.trim();

    if (!message) return;

    addMessage(message, "user");

    userInput.value = "";

    const button = chatForm.querySelector("button");
    button.disabled = true;

    try {

        const response = await fetch("/chat", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: message
            })
        });

        const result = await response.json();

        if (result.response) {
            addMessage(result.response, "bot");
        } else {
            addMessage(result.error || "Something went wrong.", "bot");
        }

    } catch (error) {

        addMessage("Unable to connect to the AI server.", "bot");

    } finally {

        button.disabled = false;
        userInput.focus();

    }

});
