async function scanAPK(){

  const filename = document.getElementById("filename").value
  const packageName = document.getElementById("package").value
  const cert = document.getElementById("cert").value
  const hash = document.getElementById("hash").value

  const resultBox = document.getElementById("apkResult")

  resultBox.innerHTML = "Analysing APK..."

  try{

    const response = await fetch(
      "http://127.0.0.1:8000/api/apk/scan",
      {
        method:"POST",

        headers:{
          "Content-Type":"application/json"
        },

        body:JSON.stringify({
          filename:filename,
          package_name:packageName,
          cert_issuer:cert,
          sha256_hash:hash
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