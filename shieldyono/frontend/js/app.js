console.log("ShieldYONO Frontend Loaded")

document.addEventListener("DOMContentLoaded", () => {

  const hero = document.querySelector(".hero")

  hero.style.opacity = "0"

  setTimeout(() => {
    hero.style.transition = "1s"
    hero.style.opacity = "1"
  }, 300)

})