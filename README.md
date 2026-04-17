# Keycloak SberPDI Murmur3 IdP Mapper

Плагин для Keycloak в формате **Identity Provider Mapper**.
Он работает только в потоке входа через внешний OIDC Identity Provider.

## Что делает

1. Показывает в конфиге маппера чекбоксы для claim из входящего JSON (token payload).
2. Берет значения только по отмеченным claim.
3. Формирует стабильную строку как конкатенацию value выбранных claim без разделителей.
4. Опционально добавляет `staticWord` в конец этой строки.
5. Считает `murmurhash3 (128-bit)`.
6. Сохраняет значение в формате UUID в user attribute (по умолчанию `profileHash`).

Для дополнительных полей есть `Custom claims` (через запятую).

Для массивов значения склеиваются через запятую.
Источник для хэша (`source`) совместим с соседним Go-сервисом: это просто склейка value-полей по порядку + `staticWord` (если включен).

## Сборка

```bash
mvn clean package
```

Результат: `target/keycloak-user-hash-plugin-1.0.0.jar`

## Установка

1. Скопировать JAR в `/opt/keycloak/providers`.
2. Выполнить:

```bash
bin/kc.sh build
bin/kc.sh start
```

## Настройка в админке

1. `Identity providers` -> нужный OIDC provider -> `Mappers` -> `Add mapper`.
2. Выбрать mapper type: `SberPDI Murmur3 Hash Mapper`.
3. Настроить параметры:
   - отметить нужные чекбоксы `Use claim: ...`
   - при необходимости заполнить `Custom claims`
   - `Use userInfo endpoint`: `ON` чтобы догружать claims из userInfo
   - `Include static word`: `ON/OFF`
   - `Static word`: `scim-adapter`
   - `Target user attribute`: `profileHash`
   - `Log debug`: `ON` на время диагностики

## Поведение

- Маппер срабатывает и для `importNewUser`, и для `updateBrokeredUser`.
- До маппинга пишет входной снимок пользователя (`BrokeredIdentityContext`): базовые поля, attributes, access/id token payload, token response и userInfo (при `Log debug = ON`).
- Если ни один выбранный claim не найден, пишется warning в лог и атрибут не меняется.
- Если значения найдены, пишется info-лог с режимом (`import`/`update`) и источниками (`context-attribute`/`access-token-payload`/`id-token-payload`/`user-info`).
