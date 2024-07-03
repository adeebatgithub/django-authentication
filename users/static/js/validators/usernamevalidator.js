

const USERNAME_ID = "id_username"
const MESSAGE_ID = "validator-message"
const MIN_LENGTH = 5
const MAX_LENGTH = 15
const REGEX = /^[a-zA-Z0-9_]+$/

function validateUsername(username) {
    if (username.length < MIN_LENGTH || username.length > MAX_LENGTH) {
        return {
            valid: false,
            message: `Username must be between ${MIN_LENGTH} and ${MAX_LENGTH} characters long.`
        };
    }

    if (!REGEX.test(username)) {
        return {
            valid: false,
            message: 'Username can only contain letters, numbers, and underscores.'
        };
    }

    return {
        valid: true,
        message: 'Username is valid.'
    };
}

document.addEventListener("DOMContentLoaded", () => {
    const usernameInput = document.getElementById(USERNAME_ID)
    const feedback = document.getElementById(MESSAGE_ID)

    usernameInput.addEventListener("input", () => {
        const result = validateUsername(usernameInput.value)

        if (!result.valid) {
            feedback.style.diaplay = "block"
            feedback.textContent = result.message
        }
    })
})
