const SERVER_PORT = 3002;

const uap = require("ua-parser-js");
const express = require("express");

const app = express();
app.disable("x-powered-by");

app.use((req, res, next) => {
    if (typeof(req.headers["content-type"]) === "undefined") {
        req.headers["content-type"] = "application/json; charset=UTF-8";
    }
    req.parsedUserAgent = uap.UAParser(req.header("user-agent"));
    console.log("==========");
    console.log(`--- ${req.parsedUserAgent.engine.name} ${req.parsedUserAgent.browser.name} (${req.header("content-type")}) ${req.method} - ${req.url}:`);
    next();
});


app.use(express.json({
    "type": [
        "application/csp-report",   // Gecko Firefox
        "application/reports+json", // Blink Edge, Blink Chrome
        "application/json"
    ]
}));


function processReportItem(item) {
    let msg = `Violation of ${item["violated-directive"]}.`;
    if (item["document-uri"] === item["source-file"] || typeof(item["source-file"] === "undefined")) {
        msg += ` Problem(s) in ${item["document-uri"]}.`;
    } else {
        msg += ` Problem(s) at ${item["document-uri"]} in ${item["source-file"]}.`;
    }
    if (item["blocked-uri"] === "inline") {
        let _ = "";
        if (typeof(item["line-number"]) !== "undefined") _ += ` Line ${item["line-number"]}`;
        if (typeof(item["column-number"]) !== "undefined") _ += `, column ${item["column-number"]}`;
        if (_ !== "") msg += `${_}.`;
    } else {
        msg += ` Blocked URI is ${item["blocked-uri"]}.`;
    }
    return msg;
}


app.post("/report-uri", (req, res) => {
    const csp = req.body["csp-report"];
    const msg = processReportItem(csp);
    const output = {
        "timestamp": Date.now(),
        "blocked-uri": csp["blocked-uri"],
        "line-number": csp["line-number"],
        "column-number": csp["column-number"],
        "document-uri": csp["document-uri"],
        "source-file": csp["source-file"],
        "violated-directive": csp["violated-directive"],
        "original-policy": csp["original-policy"],
        "message": msg
    };
    console.log("OUTPUT:");
    console.log(output);
    res.status(200).send({ "received": true });
});


app.post("/report-to", (req, res) => {
    if (!Array.isArray(req.body)) {
        req.body = [ req.body ];
    }
    let items = [];
    const now = Date.now();
    for (let item of req.body) {
        let newItem = {
            "blocked-uri": item["body"]["blockedURL"],
            "line-number": item["body"]["lineNumber"],
            "column-number": item["body"]["columnNumber"],
            "document-uri": item["body"]["documentURL"],
            "source-file": item["body"]["sourceFile"],
            "violated-directive": item["body"]["effectiveDirective"],
            "original-policy": item["body"]["originalPolicy"]
        };
        if (typeof(item["age"]) !== "undefined") newItem["actual-timestamp"] = now - item["age"];
        newItem["message"] = processReportItem(newItem);
        items.push(newItem);
    }
    const output = {
        "timestamp": now,
        "items": items
    };
    console.log("OUTPUT:");
    console.log(output);
    res.status(200).send({ "received": true });
});


app.listen(SERVER_PORT, async () => {
    console.log(`csp-report-to-target listening on port ${SERVER_PORT}`);
});
