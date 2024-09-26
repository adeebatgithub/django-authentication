const PASSWORD_ID = "id_password1"
const PASSWORD_FEEDBACK_ID = "password-message"
const CONFIRM_PASSWORD_ID = "id_password2"
const CONFIRM_PASSWORD_FEEDBACK_ID = "password confirmation-message"


function validatePassword(password) {
    let errorMessages = []
    const patterns = {
        lowercase: /[a-z]/,
        uppercase: /[A-Z]/,
        digit: /\d/,
        special: /[!@#$%^&*()\-_=+{};:,<.>\\|~]/
    }

    const minLength = 8
    const minCharacterTypes = 3

    if (password.length < minLength) {
        errorMessages.push("Password must be at least 8 characters long")
    }

    // Check character types
    let typesCount = 0
    for (const pattern of Object.values(patterns)) {
        if (pattern.test(password)) {
            typesCount++;
        }
    }

    if (typesCount < minCharacterTypes) {
        errorMessages.push(`Password must contain at least ${minCharacterTypes} of the following: lowercase letters, uppercase letters, digits, special characters`)
    }
    return errorMessages
}

document.addEventListener("DOMContentLoaded", () => {

    let errorHTML = (m) => {
        let listItems = m.map((v) => `<li>${v}</li>`).join('')
        return `<ul>${listItems}</ul>`
    }

    const passwordInput = document.getElementById(PASSWORD_ID)
    const feedback = document.getElementById(PASSWORD_FEEDBACK_ID)

    passwordInput.addEventListener("input", () => {
        if (!passwordInput.value) {
            feedback.innerHTML = null
            return 0
        }
        const errorMessages = validatePassword(passwordInput.value)
        if (errorMessages) {
            feedback.innerHTML = errorHTML(errorMessages)
        }
    })

    const passwConfirmInput = document.getElementById(CONFIRM_PASSWORD_ID)
    const passwCnfrmFeedback = document.getElementById(CONFIRM_PASSWORD_FEEDBACK_ID)

    passwConfirmInput.addEventListener("input", () => {
        if (!passwConfirmInput.value) {
            passwCnfrmFeedback.innerHTML = null
        }
        if (passwConfirmInput.value !== passwordInput.value) {
            passwCnfrmFeedback.innerHTML = errorHTML(["The passwords not matching"])
        }
        if (passwConfirmInput.value === passwordInput.value) {
            passwCnfrmFeedback.innerHTML = null
        }

    })
})
