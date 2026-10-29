from django.contrib import admin

from .models import CloudResource, ConfigurationSnapshot, NetworkRelationship


@admin.register(ConfigurationSnapshot)
class SnapshotAdmin(admin.ModelAdmin):
    list_display = ("id", "project", "version", "source_type", "imported_at")
    readonly_fields = [f.name for f in ConfigurationSnapshot._meta.fields]


admin.site.register(CloudResource)
admin.site.register(NetworkRelationship)
