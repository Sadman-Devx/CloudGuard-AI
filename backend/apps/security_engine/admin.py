from django.contrib import admin

from .models import AnalysisRun, SecurityFinding

admin.site.register(AnalysisRun)
admin.site.register(SecurityFinding)