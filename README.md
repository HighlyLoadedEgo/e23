# Про токены, JSON Web Tokens (JWT), аутентификацию и авторизацию. Token-Based Authentication

## Основы:

__Аутентификация(authentication, от греч. αὐθεντικός [authentikos] – реальный, подлинный; от αὐθέντης [authentes] – автор)__ - это процесс проверки учётных данных пользователя (логин/пароль). Проверка подлинности пользователя путём сравнения введённого им логина/пароля с данными сохранёнными в базе данных.

__Авторизация(authorization — разрешение, уполномочивание)__ - это проверка прав пользователя на доступ к определенным ресурсам.
 
Например после аутентификации юзер _**sasha**_ получает право обращатся и получать от ресурса __"super.com/vip"__ некие данные. Во время обращения юзера _**sasha**_ к ресурсу __vip__ система авторизации проверит имеет ли право юзер обращатся к этому ресурсу (проще говоря переходить по неким разрешенным ссылкам)

1. Юзер c емайлом _**sasha_gmail.com**_ успешно прошел аутентификацию
2. Сервер посмотрел в БД какая роль у юзера
3. Сервер сгенерил юзеру токен с указанной ролью
4. Юзер заходит на некий ресурс используя полученный токен
5. Сервер смотрит на права(роль) юзера в токене и соотвественно пропускает или отсекает запрос

Собственно п.5 и есть процесс __авторизации__.

*Дабы не путатся с понятиями __Authentication/Authorization__ можно использовать псевдонимы __checkPassword/checkAccess__(я так сделал в своей API)*

__JSON Web Token (JWT)__ — содержит три блока, разделенных точками: заголовок(__header__), набор полей (__payload__) и __сигнатуру__. Первые два блока представлены в JSON-формате и дополнительно закодированы в формат base64. Набор полей содержит произвольные пары имя/значения, притом стандарт JWT определяет несколько зарезервированных имен (iss, aud, exp и другие). Сигнатура может генерироваться при помощи и симметричных алгоритмов шифрования, и асимметричных. Кроме того, существует отдельный стандарт, отписывающий формат зашифрованного JWT-токена.

Пример подписанного JWT токена (после декодирования 1 и 2 блоков):
```
{ alg: "HS256", typ: "JWT" }.{ iss: "auth.myservice.com", aud: "myservice.com", exp: 1435937883, userName: "John Smith", userRole: "Admin" }.S9Zs/8/uEGGTVVtLggFTizCsMtwOJnRhjaQ2BMUQhcY
```

__Токены__ предоставляют собой средство __авторизации__ для каждого запроса от клиента к серверу. Токены(и соотвественно сигнатура токена) генерируются на сервере основываясь на секретном ключе(который хранится на сервере) и __payload'e__. Токен в итоге хранится на клиенте и используется при необходимости __авторизации__ како-го либо запроса. Такое решение отлично подходит при разработке SPA.

При попытке хакером подменить данные в __header'ре__ или __payload'е__, токен cтанет не валидным, поскольку сигнатура не будет соответствовать изначальным значениям. А возможность сгенерировать новую сигнатуру у хакера отсутствует, поскольку секретный ключ для зашифровки лежит на сервере.

__access token__ - используется для __авторизации запросов__ и хранения дополнительной информации о пользователе (аля __user_id__, __user_role__ или еще что либо, эту информацию также называет __payload__)

__refresh token__ - выдается сервером по результам успешной аутентификации и используется для получения нового __access token'a__ и обновления __refresh token'a__

Каждый токен имеет свой срок жизни, например __access__: 30мин, __refresh__: 60дней

__Поскольку токены это не зашифрованная информация крайне не рекомендуется хранить в них такую информацию как пароли.__

__Роль рефреш токенов и зачем их хранить в БД.__ Рефреш на сервере хранится для учета доступа и инвалидации краденых токенов. Таким образом сервер наверняка знает о клиентах которым стоит доверять(кому позволено авторизоваться). Если не хранить рефреш токен в БД то велика вероятность того что токены будут бесконтрольно гулять по рукам злоумышленников. Для отслеживания которых нам прийдется заводить черный список и периодически чистить его от просроченных. В место этого мы храним лимитированный список белых токенов для каждого юзера отдельно и в случае кражи у нас уже есть механизм противодействия(описано ниже).

__Хранение токенов в HTTP-only и Secure куках является альтернативным подходом для повышения безопасности.__ Такие куки недоступны для JavaScript, что защищает токены от кражи через XSS-атаки. Использование Secure атрибута гарантирует, что токены передаются только по HTTPS, исключая их утечку через незащищенные соединения.
Основное преимущество хранения токенов в куках заключается в их встроенной привязке к домену и автоматической отправке браузером с каждым запросом. Это устраняет необходимость хранения токенов на стороне клиента (в localStorage или sessionStorage), где они могут быть легко скомпрометированы.
Однако, чтобы снизить риски CSRF-атак, необходимо дополнительно использовать CSRF-токены, которые передаются в заголовках запросов и проверяются сервером. Это предотвращает несанкционированное использование куков злоумышленниками.
Таким образом, куки могут быть безопасным способом хранения токенов при соблюдении следующих условий:

1. HTTP-only и Secure атрибуты для защиты от XSS и передачи только по HTTPS.
2. Использование SameSite для ограничения межсайтового доступа к кукам.
3. Реализация защиты от CSRF через проверку токенов или реферальных заголовков.

При утечке токенов, хранящихся в куках, сервер может использовать механизм инвалидации токенов в базе данных, сохраняя список активных токенов для каждого пользователя, чтобы противодействовать злоумышленникам.

## Плюсы и минусы
JSON Web Token (JWT) решает множество задач, связанных с безопасностью, аутентификацией и авторизацией. Вот основные проблематики, которые решает использование JWT:

1. Масштабируемая аутентификация
Проблема: Сессионная аутентификация требует хранения данных о сессии на сервере. Это усложняет масштабирование приложения, так как сессии нужно синхронизировать между серверами.
Решение JWT: Вся информация о пользователе и его правах упакована в токен. Сервер не хранит сессии, что позволяет масштабировать приложение горизонтально без дополнительной синхронизации.
2. Удобная передача данных между клиентом и сервером
Проблема: Традиционные методы авторизации могут быть тяжеловесными (например, использование сложных куки или больших запросов).
Решение JWT: Токен — это компактная строка, которая легко передается через заголовки HTTP, query параметры или куки.
3. Безопасность и защита данных
Проблема: Данные могут быть подделаны или изменены злоумышленниками.
Решение JWT: Используется цифровая подпись (HMAC или RSA), которая гарантирует, что данные внутри токена не были изменены. Сервер может легко проверить валидность токена.
4. Разделение аутентификации и авторизации
Проблема: В монолитных приложениях авторизация часто тесно связана с аутентификацией, что делает систему негибкой.
Решение JWT: Позволяет разделить процесс аутентификации и авторизации. Например, аутентификацию можно выполнять через OAuth-сервер, а авторизацию проверять локально на основе данных в токене.
5. Одноразовая и ограниченная по времени аутентификация
Проблема: Сессионные ключи могут быть действительными слишком долго или использоваться повторно.
Решение JWT: Токены имеют срок действия (exp). Это позволяет ограничить время использования токена и предотвратить его повторное использование.
6. Поддержка авторизации в распределенных системах
Проблема: В микросервисной архитектуре необходимо передавать информацию о пользователе между сервисами.
Решение JWT: Токен можно передать между сервисами для проверки прав доступа без необходимости обращаться к центральному серверу.
7. Интеграция с клиентами
Проблема: Разные типы клиентов (веб, мобильные приложения) требуют единого подхода к аутентификации.
Решение JWT: Удобно использовать токен для авторизации на разных клиентах, поскольку он легко интегрируется с API и поддерживается в стандартах (например, OAuth 2.0).
8. Проблема защиты от CSRF
Проблема: Сессионные данные, хранящиеся в куках, подвержены атаке CSRF.
Решение JWT: Хранение токена в заголовках (например, Authorization: Bearer <token>) делает приложение менее уязвимым к CSRF.
Минусы JWT (на которые стоит обратить внимание):
Невозможно отозвать токен до истечения его срока действия, если не использовать черные списки.
Длина токена может увеличиваться при добавлении дополнительных данных (payload).
Если токен попадает в руки злоумышленника, он может быть использован до истечения срока действия.
JWT особенно эффективен в микросервисах, API-ориентированных приложениях и системах с масштабируемой архитектурой.

## закоментить код; наверное, можно разбить куски кода:
## создание класса; его характеристики; описание структуры, что делается

## Реализации работы с JWT
Рассмотрим, как можно реализовать работу с токенами в виде удобного класса.
```python
class JWTManager:
    def __init__(self, jwt_config: AuthConfig) -> None:
        self._jwt_config = jwt_config

    def create_token_pair(self, subject: UserSubject) -> TokensData:
        """Function to create jwt pair."""
        access_token = self._create_access_token(subject=subject)
        refresh_token = self._create_refresh_token(subject=subject)

        return TokensData(access_token=access_token, refresh_token=refresh_token)

    def refresh_tokens(self, refresh_token: str) -> str:
        """Refresh token and get new access token."""
        payload = self.decode_token(
            token=refresh_token, secret_key=self._jwt_config.REFRESH_SECRET
        )
        return self.create_token_pair(subject=UserSubject.model_validate(payload))

    def decode_token(
        self, token: str, secret_key: str | None = None
    ) -> UserTokenPayload:
        """Decodes a JWT token to extract the payload."""
        if not secret_key:
            secret_key = self._jwt_config.ACCESS_SECRET
        try:
            payload = jwt.decode(
                token,
                secret_key,
                algorithms=[self._jwt_config.ALGORITHM],
            )
        except ExpiredSignatureError:
            raise TokenExpiredError()
        except JWTError as err:
            raise InvalidTokenError() from err

        return UserTokenPayload(**payload)

    def _create_access_token(self, subject: UserSubject) -> str:
        """Creates an access token for a given user."""
        access_token = self._create_jwt_token(
            subject=subject,
            expire_minutes=self._jwt_config.ACCESS_TOKEN_EXPIRE_MINUTES,
            secret_key=self._jwt_config.ACCESS_SECRET,
        )

        return access_token

    def _create_refresh_token(self, subject: UserSubject) -> str:
        """Creates a refresh token for a given user."""
        access_token = self._create_jwt_token(
            subject=subject,
            expire_minutes=self._jwt_config.REFRESH_TOKEN_EXPIRE_MINUTES,
            secret_key=self._jwt_config.REFRESH_SECRET,
        )

        return access_token

    def _create_jwt_token(
        self, subject: UserSubject, expire_minutes: int, secret_key: str
    ) -> str:
        """Function to create jwt token."""
        iat = datetime.datetime.now(datetime.UTC)
        expires_delta = iat + datetime.timedelta(minutes=expire_minutes)

        payload = {
            "iat": iat,
            "exp": expires_delta,
            "id": str(subject.id),
        }

        return jwt.encode(payload, secret_key, algorithm=self._jwt_config.ALGORITHM)
```
Класс JWTManager предоставляет функционал для работы с JWT и содержит следующие основные методы:

1. create_token_pair: Генерирует пару токенов (access и refresh) для указанного пользователя. Access-токен предназначен для краткосрочного использования, а refresh-токен — для получения новых токенов.

2. refresh_tokens: Обновляет токены на основе переданного refresh-токена. Если токен валиден, создается новая пара токенов.

3. decode_token: Декодирует токен и извлекает из него полезную нагрузку (payload). Метод использует переданный секретный ключ и алгоритм шифрования, определённый в конфигурации.

4. Приватные методы для создания токенов:
   1. _create_access_token: Создает access-токен.
   2. _create_refresh_token: Создает refresh-токен.
   3. _create_jwt_token: Генерирует JWT с определенным временем истечения, полезной нагрузкой и ключом шифрования.

Методика работы основана на конфигурации, передаваемой через объект AuthConfig, что обеспечивает гибкость настройки (например, время истечения токенов, ключи шифрования).

## Схема создания/использования токенов (api/auth/login):
1. Пользователь логинится в приложении, передавая логин/пароль на сервер
2. Сервер проверят подлинность логина/пароля, в случае удачи генерирует и отправляет клиенту два токена(__access, refresh__) и время смерти __access token'а__ (`expires_in` поле, в __unix timestamp__). Также в __payload__ __refresh token'a__ добавляется __user_id__
3. Клиент сохраняет токены и время смерти __access token'а__, используя __access token__ для последующей авторизации запросов
4. Перед каждым запросом клиент предварительно проверяет время жизни __access token'а__ (из `expires_in`)и если оно истекло  использует __refresh token__ чтобы обновить __ОБА__ токена и продолжает использовать новый __access token__
```python
@router.post(
    "/api/auth/login",
    response_model=OkResponse[TokensResponseSchema],
    responses={
        status.HTTP_200_OK: {"model": OkResponse[TokensResponseSchema]},
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse[AuthenticationError]},
    },
    status_code=status.HTTP_200_OK,
)
async def authenticate_user(
    username: str,
    password: str,
    jwt_manager: Annotated[JWTManager, Depends(jwt_manager_stub)],
):
    user_repo = UserRepository(session=session)
    use_case = AuthenticateUserUseCase(user_repo=user_repo, jwt_manager=jwt_manager)
    result = await use_case(username=username, password=password)

    return OkResponse(result=result)
```
## Схема рефреша токенов (одна сессия/устройство, api/auth/refresh-tokens):
1. Клиент(фронтенд) проверяет перед запросом не истекло ли время жизни __access token'на__
2. Если истекло клиент отправляет на `auth/refresh-token` URL __refresh token__
3. Сервер берет __user_id__ из __payload'a__ __refresh token'a__ по нему ищет в БД запись данного юзера и достает из него __refresh token__
4. Сравнивает __refresh token__ клиента с __refresh token'ом__ найденным в БД
5. Проверяет валидность и срок действия __refresh token'а__
6. В случае успеха сервер: 
    1. Создает и перезаписывает __refresh token__ в БД
    2. Создает новый __access token__
    3. Отправляет оба токена и новый `expires_in` __access token'а__ клиенту
7. Клиент повторяет запрос к API c новым __access token'ом__
```python
@router.post(
    "/api/auth/refresh-tokens",
    response_model=OkResponse[TokensResponseSchema],
    responses={
        status.HTTP_200_OK: {"model": OkResponse[TokensResponseSchema]},
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse[Union[TokenExpiredError, InvalidTokenError]]
        },
    },
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer())],
    jwt_manager: Annotated[JWTManager, Depends(jwt_manager_stub)],
):
    use_case = RefreshTokensUseCase(jwt_manager=jwt_manager)
    result = use_case(refresh_token=credentials.credentials)

    return OkResponse(result=result)
```
__С такой схемой юзер сможет быть залогинен только на одном устройстве.__ Тоесть в любом случае при смене устройства ему придется логинится заново.

__Если рассматривать возможность аутентификации на более чем одном девайсе/браузере(мульти сессии):__ необходимо хранить весь список валидных рефреш токенов юзера. Если юзер авторизовался более чем на ±10ти устройствах(что есть весьма подозрительно), автоматически инвалидоровать все рефреш токены кроме текущего и отправлять email с security уведомлением. Как вариант список токенов можно хранить в jsonb(если используется PostgreSQL).

## Ключевой момент:
В момент рефреша то есть обновления __access token'a__ обновляются __ОБА__ токена. Но как же __refresh token__ может сам себя обновить, он ведь создается только после успешной аунтефикации ? __refresh token__ в момент рефреша сравнивает себя с тем __refresh token'ом__ который лежит в БД и вслучае успеха, а также если у него не истек срок, система рефрешит токены. __Внимание__ при обновлении __refresh token'a__ продливается также и его срок жизни.

Возникает вопрос зачем __refresh token'y__ срок жизни, если он обновляется каждый раз при обновлении __access token'a__ ? Это сделано на случай если юзер будет в офлайне более 60 дней, тогда прийдется заново вбить логин/пароль.

## В случае кражи токенов (когда юзер логинится только с одного устройства: одна сессия):

1. Хакер воспользовался __access token'ом__
2. Закончилось время жизни __access token'на__
3. __Клиент хакера__ отправляет __refresh token__
4. Хакер получает новую пару токенов 
5. На сервере создается новая пара токенов(__"от хакера"__)
5. Юзер пробует зайти на сервер >> обнаруживается что токены невалидны
6. Сервер перенаправляет юзера на форму аутентификации
7. Юзер вводит логин/пароль
8. Создается новая пара токенов >> пара токенов __"от хакера"__ становится не валидна

__Проблема:__ Поскольку __refresh token__ продлевает срок своей жизни каждый раз при рефреше токенов >> хакер пользуется токенами до тех пор пока юзер не залогинится.

### Чтиво:
- Заметка базируется на: https://habrahabr.ru/company/Voximplant/blog/323160/
- https://tools.ietf.org/html/rfc6749
- https://www.digitalocean.com/community/tutorials/oauth-2-ru
- https://jwt.io/introduction/
- https://auth0.com/blog/using-json-web-tokens-as-api-keys/
- https://auth0.com/blog/cookies-vs-tokens-definitive-guide/
- https://auth0.com/blog/ten-things-you-should-know-about-tokens-and-cookies/
- https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/
- https://habr.com/company/dataart/blog/262817/
- https://habr.com/post/340146/
- https://habr.com/company/mailru/blog/115163/
- https://scotch.io/tutorials/authenticate-a-node-js-api-with-json-web-tokens
- https://www.youtube.com/watch?v=Ngh3KZcGNaU
- https://www.youtube.com/playlist?list=PLvTBThJr861y60LQrUGpJNPu3Nt2EeQsP
- https://egghead.io/courses/json-web-token-jwt-authentication-with-node-js
- https://www.digitalocean.com/community/tutorials/oauth-2-ru
- https://github.com/shieldfy/API-Security-Checklist/blob/master/README-ru.md

### Почему JWT плохо
- http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/
- http://cryto.net/~joepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/
- https://medium.com/@cjainn/anatomy-of-a-jwt-token-part-1-8f7616113c14
- https://medium.com/@cjainn/anatomy-of-a-jwt-token-part-2-c12888abc1a2
- https://scotch.io/bar-talk/why-jwts-suck-as-session-tokens
- https://t.me/why_jwt_is_bad