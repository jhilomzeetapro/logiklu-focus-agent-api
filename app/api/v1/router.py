from fastapi import APIRouter

from app.api.v1.endpoints import health, auth_test, oauth, instructions, roles, users, focus_company_intelligence, focus_accounts, focus_account_intelligence, focus_contacts, focus_report, leadforms, campaigns, client_apiusage, accounts, contacts, deals, activities, notes, attachments, deploy_check, mobile_auth, device_auth, mail


api_router = APIRouter()

api_router.include_router(
    health.router,
    tags=["Health"]
)

api_router.include_router(
    auth_test.router,
    tags=["Authentication"]
)

api_router.include_router(
    oauth.router,
    tags=["OAuth"]
)

api_router.include_router(
    roles.router,
    tags=["Roles"]
)

api_router.include_router(
    users.router,
    tags=["Users"]
)

api_router.include_router(
    instructions.router,
    tags=["Instructions"]
)

api_router.include_router(
    focus_company_intelligence.router,
    tags=["Focus Intelligence"]
)

api_router.include_router(
    focus_accounts.router,
    tags=["Focus Accounts"]
)

api_router.include_router(
    focus_account_intelligence.router,
    tags=["Focus Account Intelligence"]
)

api_router.include_router(
    focus_contacts.router,
    tags=["Focus Contacts"]
)

api_router.include_router(
    focus_report.router,
    tags=["Focus Report"]
)

api_router.include_router(
    leadforms.router,
    tags=["Leadforms"]
)

api_router.include_router(
    campaigns.router,
    tags=["Email Campaigns"]
)

api_router.include_router(
    client_apiusage.router,
    tags=["API Usage"]
)

api_router.include_router(
    accounts.router,
    tags=["Accounts"]
)

api_router.include_router(
    contacts.router,
    tags=["Contacts"]
)

api_router.include_router(
    deals.router,
    tags=["Deals"]
)

api_router.include_router(
    activities.router,
    tags=["Activities"]
)

api_router.include_router(
    notes.router,
    tags=["Notes"]
)

api_router.include_router(
    attachments.router,
    tags=["Attachments"]
)

api_router.include_router(
    deploy_check.router,
    tags=["Deploy Check"]
)

api_router.include_router(
    mobile_auth.router,
    tags=["Mobile Authentication"],
)

api_router.include_router(
    device_auth.router,
    tags=["Device Authentication"],
)

api_router.include_router(
    mail.router,
    tags=["Mail"],
)