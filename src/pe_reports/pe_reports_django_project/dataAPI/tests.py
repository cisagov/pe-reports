# Third-Party Libraries
from home.models import MatVwOrgsAllIps

ip_address = {"3.15.167.135"}

# Note: This could be inefficient for large ip_addresses arrays.
queryset = MatVwOrgsAllIps.objects.filter(
    ip_addresses__contains=ip_address
)  # Removed the []

# To get cyhy_db_name values:
cyhy_db_name_values = queryset.values_list("cyhy_db_name", flat=True)

# If you want to print the values:
for name in cyhy_db_name_values:
    print(name)
