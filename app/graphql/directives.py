from __future__ import annotations
from functools import wraps
from ariadne import SchemaDirectiveVisitor
from graphql import default_field_resolver

class IsAuthenticatedDirective(SchemaDirectiveVisitor):
    def visit_field_definition(self, field, object_type):
        """Настраивает резолвер поля GraphQL при применении директивы схемы.

        Параметры:
            self (IsAuthenticatedDirective): экземпляр класса IsAuthenticatedDirective, переданный Python.
            field: определение поля GraphQL, обрабатываемое директивой.
            object_type: тип GraphQL-объекта, переданный фреймворком.

        Возвращает:
            То же определение поля GraphQL после установки обёрнутого резолвера (тип: GraphQLField).
        """
        original_resolver = field.resolve or default_field_resolver

        @wraps(original_resolver)
        def wrapped_resolver(obj, info, **kwargs):
            """Вызывает исходный GraphQL-резолвер с аргументами, обработанными директивой.

            Параметры:
                obj: родительский объект поля, переданный GraphQL-фреймворком.
                info: контекст выполнения поля, переданный GraphQL-фреймворком.
                kwargs: аргументы поля GraphQL, переданные фреймворком.

            Возвращает:
                Значение, возвращённое исходным резолвером (тип определяется реализацией этого резолвера).
            """
            user = info.context.get("user")
            if user is None:
                raise PermissionError("Authentication required")
            return original_resolver(obj, info, **kwargs)

        field.resolve = wrapped_resolver
        return field

class IsAdminDirective(SchemaDirectiveVisitor):
    def visit_field_definition(self, field, object_type):
        """Настраивает резолвер поля GraphQL при применении директивы схемы.

        Параметры:
            self (IsAdminDirective): экземпляр класса IsAdminDirective, переданный Python.
            field: определение поля GraphQL, обрабатываемое директивой.
            object_type: тип GraphQL-объекта, переданный фреймворком.

        Возвращает:
            То же определение поля GraphQL после установки обёрнутого резолвера (тип: GraphQLField).
        """
        original_resolver = field.resolve or default_field_resolver

        @wraps(original_resolver)
        def wrapped_resolver(obj, info, **kwargs):
            """Вызывает исходный GraphQL-резолвер с аргументами, обработанными директивой.

            Параметры:
                obj: родительский объект поля, переданный GraphQL-фреймворком.
                info: контекст выполнения поля, переданный GraphQL-фреймворком.
                kwargs: аргументы поля GraphQL, переданные фреймворком.

            Возвращает:
                Значение, возвращённое исходным резолвером (тип определяется реализацией этого резолвера).
            """
            user = info.context.get("user")
            if user is None:
                raise PermissionError("Authentication required")
            if not user.is_admin:
                raise PermissionError("Admin only")
            return original_resolver(obj, info, **kwargs)

        field.resolve = wrapped_resolver
        return field