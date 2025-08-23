"""
Coffeez Django Admin Configuration

This module configures the Django admin interface for Coffeez models.
Provides administrative access to Creator and CoffeePurchase data with
appropriate field restrictions and display optimizations.

Key features:
- Creator wallet addresses are read-only once set (prevents accidental changes)
- CoffeePurchase displays essential transaction information
- Proper field visibility for administrative oversight
"""

from django.contrib import admin
from .models import Creator, CoffeePurchase


class CreatorAdmin(admin.ModelAdmin):
    """
    Admin interface configuration for Creator model.
    
    Prevents modification of wallet addresses once they are set to maintain
    transaction integrity. Wallet addresses should not be changed after
    creators start receiving donations.
    """
    readonly_fields = ('wallet_address',)
    
    def get_readonly_fields(self, request, obj=None):
        """
        Dynamically set read-only fields based on object state.
        
        Args:
            request: HTTP request object
            obj: Creator instance being edited (None for new objects)
            
        Returns:
            tuple: Fields that should be read-only
        """
        # If this is an existing object with a wallet address, make it read-only
        if obj and obj.wallet_address:
            return self.readonly_fields + ('wallet_address',)
        return self.readonly_fields


class CoffeePurchaseAdmin(admin.ModelAdmin):
    """
    Admin interface configuration for CoffeePurchase model.
    
    Displays key transaction information in list view for easy monitoring
    of donation activity. Creator wallet address is read-only as it should
    not be modified after purchase creation.
    """
    list_display = ('buyer_name', 'creator', 'amount', 'creator_wallet_address', 'status')
    readonly_fields = ('creator_wallet_address',)


# Register models with their respective admin classes
admin.site.register(Creator, CreatorAdmin)
admin.site.register(CoffeePurchase, CoffeePurchaseAdmin)
