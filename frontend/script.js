document.getElementById("detectForm").addEventListener("submit", async function(e) {
    e.preventDefault();
    let features = document.getElementById("features").value.split(",").map(Number);

    let response = await fetch("http://127.0.0.1:5000/detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ features: features })
    });

    let data = await response.json();
    document.getElementById("result").innerText = "Prediction: " + (data.result === 1 ? "Threat" : "Normal");
});