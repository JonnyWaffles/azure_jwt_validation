from setuptools import setup


setup(
    name='azure_jwt_validation',
    version='0.1',
    description='Helper to validate jwt tokens signed by Azure AD.',
    url='https://github.com/JonnyWaffles/azure_jwt_validation',
    author='Jonny Fuller',
    author_email='jfuller@markelcorp.com',
    packages=[
        'azure_jwt_validation'
    ],
    install_requires=[
        'requests',
        'PyJWT',
        'cryptography'
    ],
    include_package_data=True,
    extras_require={
        'dev': ['sphinx', 'sphinx-autodoc-typehints']
    }
)
