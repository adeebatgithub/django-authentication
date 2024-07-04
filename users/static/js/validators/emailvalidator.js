const EMAIL_ID = "id_email"
const EMAIL_FEEDBACK_ID = "email address-message"
const EMAIL_REGEX = /^[a-zA-Z0-9._-]+@gmail\.com$/


function validateEmail(email) {
    let errorMessages = []
    if (!EMAIL_REGEX.test(email)) {
        errorMessages.push('email is not valid.')
    }
    return errorMessages
}

document.addEventListener("DOMContentLoaded", () => {
    const emailInput = document.getElementById(EMAIL_ID)
    const feedback = document.getElementById(EMAIL_FEEDBACK_ID)

    emailInput.addEventListener("focusout", () => {
        if (!emailInput.value) {
            feedback.innerHTML = null
            return 0
        }
        const errorMessages = validateEmail(emailInput.value)
        if (errorMessages) {
            let errorHTML = (m) => {
                let listItems = m.map((v) => `<li>${v}</li>`).join('')
                return `<ul>${listItems}</ul>`
            }
            feedback.innerHTML = errorHTML(errorMessages)
        }
    })
    emailInput.addEventListener("input", () => {
        if (!emailInput.value) {
            feedback.innerHTML = null
            return 0
        }
    })
})
