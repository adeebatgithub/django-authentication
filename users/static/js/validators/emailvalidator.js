const EMAIL_ID = "id_email"
const EMAIL_FEEDBACK_ID = "email address-message"
const EMAIL_REGEX = /^[a-zA-Z0-9._-]+@gmail\.com$/


async function validateEmail(email, socket) {
    let errorMessages = []
    if (!EMAIL_REGEX.test(email)) {
        errorMessages.push('email is not valid.')
    }
    const is_exists = (email) => {
        return new Promise((resolve, reject) => {
            socket.send(JSON.stringify({ email: email }))
            socket.onmessage = (e) => {
                const data = JSON.parse(e.data)
                resolve(data.message)
            }
            socket.onerror = (err) => {
                reject(err)
            }
        })
    }
    if (await is_exists(email)) {
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
        const errorMessages = await validateEmail(emailInput.value, socket)
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
