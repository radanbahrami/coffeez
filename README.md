# Coffeez

A Django-based platform for content creators to receive cryptocurrency donations through virtual "coffee" purchases.

## Overview

Coffeez enables supporters to buy virtual "coffees" for their favorite creators using TRX (TRON) cryptocurrency. Each coffee costs $3 USD equivalent in TRX, with unique payment amounts generated for automatic transaction verification.

## Key Features

### Creator Management
- **Profiles**: Customizable creator profiles with usernames, display names, bios, and profile pictures
- **Authentication**: Email Login and Google OAuth integration
- **Security**: Comprehensive username validation to prevent impersonation and reserved terms
- **Dashboard**: Creator statistics showing total coffees received and estimated USD earnings

### Payment System
- **Cryptocurrency**: TRX (TRON) blockchain integration for donations
- **Unique Amounts**: Each transaction uses a slightly randomized amount for automatic verification
- **Real-time Pricing**: Live TRX-to-USD conversion using CryptoCompare API
- **Payment Tracking**: Automatic confirmation via blockchain monitoring

### Security Features
- **Bot Protection**: hCaptcha integration for all donation requests
- **Session Limits**: Maximum 50 coffees per session to prevent abuse
- **Access Control**: Session-based purchase access to prevent unauthorized viewing
- **File Security**: Profile picture sanitization and metadata removal
- **Wallet Protection**: Wallet addresses cannot be changed once set

### User Experience
- **Mobile Responsive**: Optimized for all device sizes
- **Real-time Updates**: Purchase flow with status updates
- **Social Proof**: Recent supporter display on creator profiles
- **Error Handling**: Comprehensive error messages and graceful failure handling

## Configuration

### Environment Variables
```bash
DJANGO_SECRET_KEY=your_secret_key
HCAPTCHA_SECRET=your_hcaptcha_secret
MYSQL_DATABASE=your_database_name
MYSQL_USER=your_database_user
MYSQL_PASSWORD=your_database_password
MYSQL_HOST=localhost
MYSQL_PORT=3306
```

### Database
- **Primary**: MySQL with PyMySQL adapter
- **Indexes**: Optimized for email verification and purchase queries
- **Cleanup**: Automated expired purchase removal

### External Services
- **Google OAuth**: Social authentication
- **hCaptcha**: Bot protection
- **CryptoCompare API**: TRX price data
- **TRON Blockchain**: Payment verification

## Security Considerations

### Input Validation
- All user inputs are validated and sanitized
- Custom validators prevent malicious usernames
- File uploads are restricted and processed securely

### Authentication & Authorization
- Email verification required for all accounts
- Session-based access control for sensitive operations
- Social authentication with custom adapter

### Financial Security
- Wallet addresses are immutable once set
- Payment amounts are unique and trackable
- Session limits prevent abuse

## Management Commands

### Cleanup Expired Purchases
```bash
python manage.py cleanup_expired_purchases
```
Removes pending purchases older than 30 minutes to maintain database hygiene.

## Development

### Project Structure
```
coffeez/
├── coffeez/              # Main Django application
│   ├── models.py         # Database models
│   ├── views.py          # View functions
│   ├── urls.py           # URL routing
│   ├── admin.py          # Admin interface
│   ├── validators.py     # Custom validation
│   ├── utils.py          # Utility functions
│   ├── adapters.py       # Social auth adapters
│   └── management/       # Custom management commands
├── core/                 # Django project settings
│   ├── settings.py       # Configuration
│   ├── urls.py           # Root URL routing
│   └── wsgi.py           # WSGI configuration
└── requirements.txt      # Python dependencies
```

### Testing
The codebase includes test files (`tests.py`) for model and view testing.

## Deployment

### Some Production Considerations
- Set `DEBUG = False` in settings
- Configure proper `ALLOWED_HOSTS`
- Use environment variables for all secrets
- Set up occasional expired purchases cleanup

## License

See LICENSE.txt for licensing information.

## Contributing

Contributions are currently not accepted.

## Author

Created by Radan Bahrami

LinkedIn: [linkedin.com/in/radanbahrami](https://www.linkedin.com/in/radanbahrami)

Website: [radanbahrami.com](https://radanbahrami.com)

## Contact Me

You can contact me via email: radanbhr@gmail.com.