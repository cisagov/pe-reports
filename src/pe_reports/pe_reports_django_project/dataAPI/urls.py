# Third-Party Libraries
from fastapi import APIRouter

# cisagov Libraries
from . import views
from ..home.models import Organizations


# router = APIRouter()
#
#
# router.get(
#     "/simulation/",
#     summary="Retrieve a list of all the simulations.",
#     tags=["simulations"],
#     response_model=Organizations,
#     name="simulations-get",
# )(views.simulations_get)
