from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField

from .models import *
from .forms import UserChangeForm, UserCreationForm


class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    list_display = ('phone', 'email', 'name', 'user_type','gender','is_admin')
    list_filter = ('is_admin',)
    fieldsets = (
        (None, {'fields': ('phone', 'password', 'user_type')}),
        ('Personal info', {'fields': ('email','name','gender')}),
		('Permissions', {'fields': ('is_admin',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'email','name', 'gender', 'user_type', 'password1', 'password2','is_admin'),
        }),
    )
    search_fields = ('phone',)
    ordering = ('phone',)
    filter_horizontal = ()


admin.site.register(User, UserAdmin)
admin.site.unregister(Group)
admin.site.register(Doctor)
admin.site.register(Patient)
