const EMAIL_ID = "id_email"
const EMAIL_FEEDBACK_ID = "email address-message"
const EMAIL_REGEX = /^[a-zA-Z0-9._-]+@gmail\.com$/


async function validateEmail(email) {
    let errorMessages = []
    if (!EMAIL_REGEX.test(email)) {
        errorMessages.push('email is not valid.')
    }
    async function isExists(email) {
        try {
            const response = await fetch(`/validate/email/${encodeURIComponent(email)}/`)
            if (!response.ok) {
                console.error("response status: ", response.status)
            }
            const data = await response.json();
            return data.exists
        } catch (error) {
            console.error('Error:', error);
            return false
        }
    }
    if (await isExists(email)) {
        errorMessages.push("Email already exists");
    }
    return errorMessages
}

document.addEventListener("DOMContentLoaded", () => {
    const emailInput = document.getElementById(EMAIL_ID)
    const feedback = document.getElementById(EMAIL_FEEDBACK_ID)

    emailInput.addEventListener("focusout", async () => {
        if (!emailInput.value) {
            feedback.innerHTML = null
            return 0
        }
        const errorMessages = await validateEmail(emailInput.value)
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
