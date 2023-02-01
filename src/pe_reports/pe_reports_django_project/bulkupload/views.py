from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from django.core.validators import FileExtensionValidator, ValidationError
from django.contrib import messages
import logging

from .forms import CSVUploadForm

import csv
from io import TextIOWrapper

from django.views.generic.edit import FormView

from .forms import CSVUploadForm


LOGGER = logging.getLogger(__name__)

class CustomCSVView(TemplateView):
    template_name = "bulk_upload/upload.html"
    form_class = CSVUploadForm


class CustomCSVForm(FormView):
    form_class = CSVUploadForm
    template_name = 'bulk_upload/upload.html'

    success_url = reverse_lazy('bulkupload')

    def form_valid(self, form):
        validators = FileExtensionValidator(allowed_extensions=['csv'])

        csv_file = form.cleaned_data["file"]
        try:
            print(validators(csv_file))

        except ValidationError as err:

            messages.warning()


            LOGGER.info("The file extension is invalid please try again %s", err)





        # f = TextIOWrapper(csv_file.file)
        #
        # dict_reader = csv.DictReader(f)
        #
        # required_columns = ["org",
        #                     "org_code",
        #                     "root_domain",
        #                     "exec_url",
        #                     "aliases",
        #                     "premium",
        #                     "demo"]
        # # Check needed columns exist
        # for req_col in required_columns:
        #     if req_col not in dict_reader.fieldnames:
        #         raise Exception(
        #             f"A required column is missing from the uploaded CSV: '{req_col}'"
        #         )
        #
        # for row, item in enumerate(dict_reader, start=1):
        #     self.process_item(item)

        return super().form_valid(form)

    def process_item(self, item):
        # TODO: Replace with the code for what you wish to do with the row of data in the CSV.
        print(item["column_1"])
        print(item["column_2"])