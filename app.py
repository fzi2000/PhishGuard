import streamlit as st
import joblib

from phishguard import investigate_email


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="PhishGuard SOC",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

.main {
    background-color: #0b0f14;
}

.block-container {
    padding-top: 2rem;
}

.hero {
    padding: 25px;
    border-radius: 15px;
    background: linear-gradient(
        135deg,
        #111827,
        #0f172a
    );
    border: 1px solid #263244;
    margin-bottom: 25px;
}

.hero h1 {
    margin-bottom: 5px;
}

.metric-card {
    padding: 18px;
    border-radius: 12px;
    background: #111827;
    border: 1px solid #263244;
}

.threat-high {
    padding: 25px;
    border-radius: 15px;
    background: #3b1111;
    border: 1px solid #ef4444;
}

.threat-medium {
    padding: 25px;
    border-radius: 15px;
    background: #3b2b0f;
    border: 1px solid #f59e0b;
}

.threat-low {
    padding: 25px;
    border-radius: 15px;
    background: #0f2f22;
    border: 1px solid #22c55e;
}

.ioc {
    padding: 10px;
    margin: 5px 0;
    border-radius: 8px;
    background: #111827;
    border: 1px solid #263244;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():

    return joblib.load(
        "phishing_email_model.pkl"
    )


model = load_model()


# ============================================================
# HEADER
# ============================================================

st.markdown("""
<div class="hero">

<h1>🛡️ PhishGuard</h1>

<p>
AI-Powered Phishing Investigation & Threat Response
</p>

<p>
NLP Detection • IOC Extraction • URL Intelligence •
Attack Classification • MITRE ATT&CK
</p>

</div>
""", unsafe_allow_html=True)


# ============================================================
# EXAMPLE EMAILS
# ============================================================

st.subheader(" Threat Simulation")

col1, col2, col3 = st.columns(3)

if "sender" not in st.session_state:
    st.session_state.sender = ""

if "subject" not in st.session_state:
    st.session_state.subject = ""

if "body" not in st.session_state:
    st.session_state.body = ""


with col1:

    if st.button(
        "🔴 Credential Phishing",
        use_container_width=True
    ):

        st.session_state.sender = (
            "security@microsoft-account-verify.com"
        )

        st.session_state.subject = (
            "URGENT: Your Microsoft account will be suspended"
        )

        st.session_state.body = """
Your account has been flagged for suspicious activity.

You must verify your account immediately.

Please confirm your password and security information:

http://microsoft-security-login.com/verify

Failure to verify within 24 hours will result in permanent suspension.
"""


with col2:

    if st.button(
        "🟠 Invoice Fraud",
        use_container_width=True
    ):

        st.session_state.sender = (
            "billing@company-payment-alert.com"
        )

        st.session_state.subject = (
            "URGENT: Outstanding Invoice Payment"
        )

        st.session_state.body = """
Your invoice is overdue.

Please review the invoice and complete payment immediately.

Payment portal:
http://secure-payment-verification.com/invoice

Failure to pay today may result in account suspension.
"""


with col3:

    if st.button(
        "🟢 Normal Email",
        use_container_width=True
    ):

        st.session_state.sender = (
            "hr@company.com"
        )

        st.session_state.subject = (
            "Team meeting tomorrow"
        )

        st.session_state.body = """
Hi team,

Just a reminder that our weekly team meeting
will take place tomorrow at 10 AM.

Please bring your project updates.

Thanks.
"""


# ============================================================
# EMAIL INPUT
# ============================================================

st.subheader("📨 Email Investigation")

sender = st.text_input(
    "Sender",
    key="sender"
)

subject = st.text_input(
    "Subject",
    key="subject"
)

body = st.text_area(
    "Email Body",
    height=250,
    key="body"
)


# ============================================================
# ANALYZE
# ============================================================

if st.button(
    "🔎 INVESTIGATE THREAT",
    type="primary",
    use_container_width=True
):

    if not body and not subject:

        st.warning(
            "Please enter an email."
        )

    else:

        email_text = (
            subject
            + " "
            + body
        )

        # ---------------------------------------------
        # ML
        # ---------------------------------------------

        ml_probability = (
            model
            .predict_proba(
                [email_text]
            )[0][1]
        )

        # ---------------------------------------------
        # SECURITY ENGINE
        # ---------------------------------------------

        report = investigate_email(
            sender,
            subject,
            body,
            ml_probability
        )

        st.session_state.report = report


# ============================================================
# DISPLAY REPORT
# ============================================================

if "report" in st.session_state:

    report = st.session_state.report

    score = report["risk_score"]

    severity = report["severity"]

    # ========================================================
    # VERDICT
    # ========================================================

    if severity == "high":

        st.markdown(
            f"""
            <div class="threat-high">

            <h1>🚨 {report["verdict"]}</h1>

            <h2>Risk Score: {score}/100</h2>

            <p>
            Recommended Response:
            <b>{report["action"]}</b>
            </p>

            </div>
            """,
            unsafe_allow_html=True
        )

    elif severity == "medium":

        st.markdown(
            f"""
            <div class="threat-medium">

            <h1>⚠️ {report["verdict"]}</h1>

            <h2>Risk Score: {score}/100</h2>

            <p>
            Recommended Response:
            <b>{report["action"]}</b>
            </p>

            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            f"""
            <div class="threat-low">

            <h1>🟢 {report["verdict"]}</h1>

            <h2>Risk Score: {score}/100</h2>

            <p>
            Recommended Response:
            <b>{report["action"]}</b>
            </p>

            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # SECURITY LAYERS
    # ========================================================

    st.subheader(
        " Security Analysis"
    )

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:

        st.metric(
            " NLP",
            f'{report["ml_probability"]}%'
        )

    with c2:

        st.metric(
            "🔗 URL Risk",
            f'{report["url_analysis"]["max_score"]}/100'
        )

    with c3:

        st.metric(
            "👤 Sender Risk",
            f'{report["sender_score"]}/100'
        )

    with c4:

        st.metric(
            " Social Engineering",
            f'{report["language_score"]}/100'
        )

    with c5:

        st.metric(
            " Impersonation",
            f'{report["impersonation_score"]}/100'
        )


    # ========================================================
    # ATTACK CLASSIFICATION
    # ========================================================

    st.subheader(
        "🎯 Attack Classification"
    )

    for attack in report["attacks"]:

        st.info(
            f" {attack}"
        )


    # ========================================================
    # MITRE ATT&CK
    # ========================================================

    st.subheader(
        " MITRE ATT&CK Mapping"
    )

    if report["mitre"]:

        for technique in report["mitre"]:

            st.markdown(
                f"""
                **{technique["id"]} — {technique["name"]}**
                """
            )

    else:

        st.write(
            "No ATT&CK techniques mapped."
        )


    # ========================================================
    # IOCS
    # ========================================================

    st.subheader(
        " Indicators of Compromise"
    )

    iocs = report["iocs"]

    col1, col2 = st.columns(2)

    with col1:

        st.markdown(
            "### 🌐 Domains"
        )

        if iocs["domains"]:

            for domain in iocs["domains"]:

                st.code(domain)

        else:

            st.write(
                "No domains extracted."
            )


    with col2:

        st.markdown(
            "### 🔗 URLs"
        )

        if iocs["urls"]:

            for url in iocs["urls"]:

                st.code(url)

        else:

            st.write(
                "No URLs extracted."
            )


    # ========================================================
    # BRAND IMPERSONATION
    # ========================================================

    if report["brands_detected"]:

        st.subheader(
            "🎭 Brand Impersonation"
        )

        for brand in report["brands_detected"]:

            st.warning(
                f"Possible impersonation of: "
                f"**{brand.title()}**"
            )


   

    # ========================================================
    # RESPONSE
    # ========================================================

    st.subheader(
        "🛡️ Recommended Response"
    )

    if report["action"] == "BLOCK":

        st.error(
            """
            BLOCK EMAIL

            • Do not click links
            • Do not enter credentials
            • Quarantine the message
            • Report the sender
            • Investigate extracted IOCs
            """
        )

    elif report["action"] == "REVIEW":

        st.warning(
            """
            SECURITY REVIEW REQUIRED

            • Verify sender identity
            • Inspect URLs
            • Validate the request through another channel
            • Do not provide credentials
            """
        )

    else:

        st.success(
            """
            LOW RISK

            • No major threat indicators detected
            • Normal handling recommended
            """
        )
