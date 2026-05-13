async function scanURL(){

  const url = document.getElementById("urlInput").value

  const resultBox = document.getElementById("result")

  resultBox.innerHTML = "Scanning..."

  try{

    const response = await fetch(
      "http://127.0.0.1:8000/api/link/scan",
      {
        method:"POST",

        headers:{
          "Content-Type":"application/json"
        },

        body:JSON.stringify({
          url:url,
          source:"manual"
        })
      }
    )

    const data = await response.json()

    resultBox.innerHTML = `
      <h2 style="font-size:32px;">
        Verdict: ${data.verdict.toUpperCase()}
      </h2>

      <p style="margin-top:20px;">
        Risk Score: ${data.risk_score}
      </p>

      <p>
        Domain: ${data.domain}
      </p>

      <p>
        Recommendation:
        ${data.recommendation}
      </p>

      <h3 style="margin-top:20px;">
        Signals
      </h3>

      <ul>
        ${data.signals.map(s => `<li>${s}</li>`).join("")}
      </ul>
    `

  }catch(err){

    resultBox.innerHTML = `
      Backend connection failed.
    `
  }
}