const USERNAME_ID = "id_username"
const USERNAME_FEEDBACK_ID = "username-message"
const MIN_LENGTH = 5
const MAX_LENGTH = 15
const USERNAME_REGEX = /^[a-zA-Z0-9_]+$/

function validateUsername(username) {
    let errorMessages = []
    if (username.length < MIN_LENGTH || username.length > MAX_LENGTH) {
        errorMessages.push(`Username must be between ${MIN_LENGTH} and ${MAX_LENGTH} characters long.`)
    }
    if (!USERNAME_REGEX.test(username)) {
        errorMessages.push('Username can only contain letters, numbers, and underscores.')
    }
    return errorMessages
}

document.addEventListener("DOMContentLoaded", () => {
    const usernameInput = document.getElementById(USERNAME_ID)
    const feedback = document.getElementById(USERNAME_FEEDBACK_ID)

    usernameInput.addEventListener("input", () => {
        if (!usernameInput.value) {
            feedback.innerHTML = null
            return 0
        }
        const errorMessages = validateUsername(usernameInput.value)
        if (errorMessages) {
            let errorHTML = (m) => {
                let listItems = m.map((v) => `<li>${v}</li>`).join('')
                return `<ul>${listItems}</ul>`
            }
            feedback.innerHTML = errorHTML(errorMessages)
        }
    })
})
