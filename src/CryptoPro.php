<?php 

namespace CryptoProBuilder;

use BadMethodCallException;
use InvalidArgumentException;
use RuntimeException;
use FluentConsole\ConsoleRunner; // Убедитесь, что это правильный путь к вашему ConsoleRunner

class CryptoPro
{
    /**
     * @var ConsoleRunner Инстанс ConsoleRunner для выполнения команд.
     */
    protected ConsoleRunner $csp;

    /**
     * @var array Коллекция предопределенных паттернов для парсинга вывода команд.
     */
    protected array $patterns = [
        'containerFullPath' => '#\\\\.*#', // Возвращает полный путь контейнера
        'containerNameOnly' => '#\\\\([^\\\\]+)$#', // Возвращает только имя
        'hashformat' => '/^[A-Fa-f0-9]{64,128}$/', // Формат хэша (для ГОСТ Р 34.11-2012 это 64 или 128 символов)
        'hashFile' => [
            'fields' => ['hash'],
            'patterns' => [
                '/([A-F0-9]+)/i', // Возвращает hash подписанного файла
            ]
        ],
        'verifyHash' => [
            'fields' => ['status'],
            'patterns' => [
                '/File .* has been verified/i', // OK
                '/File .* was corrupted/i', // FAIL
            ]
        ],
        'signatureOwner' => '/Автор подписи:\s*(.*)/u', // Возвращает данные подписанта
        'certificatesCNOnly' => '/^Субъект\s*:\s.*?\bCN=([^,]+)/u', // Возвращает данные владельца сертификата по CN
        'certificates' => [
            'fields' => [
                'subject',
                'serialNumber',
                'sha1',
                'issued',
                'expires',
            ],
            'patterns' => [
                '/Субъект\s+:\s+.*CN=([^,]+)/u',
                '/Серийный номер\s+:\s+(.+)/',
                '/SHA1 отпечаток\s+:\s+([a-f0-9]+)/i',
                '/Выдан\s+:\s+(.+)/',
                '/Истекает\s+:\s+(.+)/',
            ]
        ]
    ];

    /**
     * @var array|null Текущий активный паттерн(ы) для парсинга вывода.
     */
    protected ?array $pattern = null;

    /**
     * @var array|null Ожидаемые поля для структурированного вывода.
     */
    protected ?array $expectedFields = null;

    /**
     * @var bool Флаг, указывающий, нужно ли структурировать выходные данные.
     */
    protected bool $structureMatches = false;

    /**
     * @var array Массив доступных команд/методов, которые могут быть вызваны динамически.
     */
    protected array $methods = [
        // Глобальные опции
        'help',            // Печатает справку по программе
        'notime',          // Не отображать время выполнения

        // Команды, специфичные для режима
        'lowenc',          // Тестирование низкоуровневого шифрования/дешифрования
        'sfenc',           // Упрощенное шифрование/дешифрование сообщений
        'lowsign',         // Тестирование низкоуровневого подписания сообщений
        'sfsign',          // Упрощенное подписание/проверка подписей сообщений
        'cmssfsign',       // Упрощенное подписания/проверка подписей сообщений (устарело)
        'ipsec',           // Тесты IPSec
        'defprov',         // Манипуляции с дефолтным провайдером
        'property',        // Получение/установка свойств сертификата для секретного ключа
        'mk',              // Инициализация получения хэша (или вычисление хэша файла в Cpverify)
        'hash',            // Получение хеша файла (или посчитать хэши файлов в cryptcp)
        'alg',             // Установить хэш-алгоритм (или алгоритм хэширования в Cpverify)
        'certkey',         // Изменить имя провайдера в сертификате секретного ключа
        'absorb',          // Поглощение всех сертификатов из контейнеров с секретным ключом
        'tlss',            // Запуск TLS сервера
        'tlsc',            // Запуск TLS клиента
        'certlic',         // Информация о лицензии сертификата
        'rc',              // Проверка подписи PKCS#10/сертификата
        'minica',          // Тест выпуска сертификатов
        'certprop',        // Показать свойства сертификата
        'sfse',            // Упрощенное тестирование SignedAndEnveloped сообщений
        'oid',             // Получение/установка информации об OID
        'change',          // Изменить пароль
        'passwd',          // Установить или изменить пароль
        'keycopy',         // Копирование контейнера
        'keyset',          // Создать или открыть ключевой контейнер
        'card',            // Информация о считывателях карт
        'enum',            // Перечисление параметров CSP
        'perf',            // Производственные тесты
        'speed',           // Тесты скорости и установка оптимальной маски функции

        // Дополнительные команды:
        'ask',             // Получить контекст csp с помощью моего сертификата (по умолчанию: нет)
        'in',              // Входной файл
        'out',             // Выходной файл
        'add',             // Добавить сертификат
        'attached',        // Встроенная подпись
        'detached',        // Отсоединенная подпись
        'base64',          // Ввод/вывод с преобразованием base64<->DER
        'addsigtime',      // Добавить атрибут времени подписи
        'cades_strict',    // Строгая генерация атрибута signingCertificateV2
        'cades_disable',   // Отключить генерацию атрибута signingCertificateV2
        'display_content', // Данные, которые должны отображаться на носителе/считывателе, встроены в содержимое сообщения
        'sign',            // Подписать сообщение (или создать подписанное сообщение в cryptcp)
        'my',              // Сертификат текущего пользователя
        'MY',              // Сертификат локальной машины
        'CERT',            // Часть имени поля Common Name или отпечаток сертификата
        'provname',        // Имя провайдера (или имя криптопровайдера в Cpverify/cryptcp)
        'provtype',        // Тип провайдера (или тип криптопровайдера в Cpverify/cryptcp)
        'cont',            // Путь к контейнеру (или имя контейнера в Cpverify/cryptcp)
        'machinekeys',     // Ключи на локальной машине
        'enum_cont',       // Перечислить контейнеры
        'verifycontext',   // Открытый контекст только для проверки
        'fqcn',            // Отобразить полное имя контейнера
        'check',           // Проверить контейнер
        'password',        // Указать пароль
        'deletekeyset',    // Удалить контейнер
        'container',       // Имя контейнера
        'contsrc',         // Имя исходного контейнера (весь путь)
        'contdest',        // Имя конечного контейнера (весь путь)
        'verify',          // Проверить файл с подписью (или проверить подпись сообщения/файла в cryptcp/Cpverify)
        'pinsrc',          // Пароль исходного контейнера
        'pindest',         // Пароль конечного контейнера
        'silent',          // Не отображать пользовательский интерфейс
        'req_compliant',   // Предварительный просмотр файла перед подписью/проверкой и проверка цепочки сертификатов (работает только с опцией '-detached')
        'list',            // Получить список сертификатов
        'store',           // Выбрать хранилище сертификатов

        // КриптоПро 5 версии (общие команды)
        'tls1_2',          // Использование TLS 1.2
        'tls1_3',          // Использование TLS 1.3
        'ecdsa',           // Подпись с использованием алгоритма ECDSA
        'aes',             // Шифрование с использованием алгоритма AES
        'rsa',             // Шифрование с использованием алгоритма RSA
        'ocsp',            // Проверка статуса сертификата через OCSP
        'csr',             // Генерация запроса на сертификат (CSR)
        'pkcs12',          // Создание файла PKCS#12
        'pkcs7',           // Создание или проверка PKCS#7 подписи
        'signfile',        // Подписать файл с помощью приватного ключа
        'verifyfile',      // Проверка файла на наличие подписи
        'p12import',       // Импорт PKCS#12 сертификатов
        'importkey',       // Импорт приватного ключа
        'exportkey',       // Экспорт приватного ключа
        'setprov',         // Установить провайдер криптографии
        'getprov',         // Получить информацию о текущем провайдере
        'backup',          // Резервное копирование ключей
        'restore',         // Восстановление ключей
        'log',             // Записать лог операций
        'audit',           // Аудит криптографических операций
        'timecheck',       // Проверка времени подписания
        'signtime',        // Время подписи
        'revoke',          // Отозвать сертификат
        'expiry',          // Проверка срока действия сертификата
        'validate',        // Проверить корректность сертификата

        // Cpverify команды
        'logfile',             // Путь к файлу лога (заменяет вывод в stdout/stderr)
        'sleep',               // Пауза перед началом выполнения (в миллисекундах)
        'wnd',                 // Показать окно с сообщением (MessageBox)
        'errwnd',              // Показать MessageBox только при ошибке
        // 'mk',               // Дублируется выше, сохранено как первое описание
        // 'verify',           // Дублируется выше, сохранено как первое описание
        'rm',                  // Вычисление хэшей для файлов из реестра
        'addreg',              // Сохранить хэш файла в реестре
        'delreg',              // Удалить хэш файла из реестра
        'rv',                  // Проверка файлов из реестра
        'xm',                  // Вычисление хэшей и сохранение в XML
        'xv',                  // Проверка целостности по XML
        'x2r',                 // Копирование хэшей из XML в реестр
        'r2x',                 // Копирование хэшей из реестра в XML
        'file_sign',           // Подпись файла с использованием контейнера
        'file_verify',         // Проверка подписи файла
        // 'alg',              // Дублируется выше, сохранено как первое описание
        'inverted_halfbytes',  // Реверс половинок байтов хэша (0 или 1)
        // 'cont',             // Дублируется выше, сохранено как первое описание
        'pin',                 // Пароль к контейнеру
        // 'provname',         // Дублируется выше, сохранено как первое описание
        // 'provtype',         // Дублируется выше, сохранено как первое описание
        'timestamp',           // Дата подписи в формате dd.mm.yyyy
        'filename',            // Имя основного файла для подписи/проверки/хэширования
        'hashvalue',           // Явно указанный хэш (если не использовать .hsh)
        'signval',             // Значение подписи (если не использовать .sgn)
        'catname',             // Имя каталога (для групповых операций)
        'in_file',             // Входной XML-файл
        'out_file',            // Выходной XML-файл

        // Методы CryptCP (добавлены без дубликатов)
        'encr',            // cryptcp: создать зашифрованное сообщение
        'decr',            // cryptcp: расшифровать сообщение
        // 'sign',           // Дублируется (есть выше как 'Подписать сообщение'), но функциональность пересекается
        // 'verify',         // Дублируется (есть выше как 'Проверить файл с подписью'), но функциональность пересекается
        'addsign',         // cryptcp: добавить подпись в сообщение
        'delsign',         // cryptcp: удалить подпись из сообщения
        'addattr',         // cryptcp: добавить в подпись неподписанный атрибут
        'signf',           // cryptcp: создать подписи файлов в 'исходный_файл.sgn'
        'vsignf',          // cryptcp: проверить подписи файлов, созданные с помощью команды '-signf'
        'addsignf',        // cryptcp: добавить подпись файла в 'исходный_файл.sgn'
        // 'hash',           // Дублируется (есть выше как 'Получение хеша файла'), но функциональность пересекается
        'vhash',           // cryptcp: проверить хэши файлов, созданные с помощью команды '-hash'
        'copycert',        // cryptcp: скопировать сертификаты в заданное хранилище
        'cspcert',         // cryptcp: скопировать сертификат из ключевого контейнера в хранилище
        'delcert',         // cryptcp: удалить сертификат из хранилища
        'listdn',          // cryptcp: вывести на экран политику имен КриптоПро УЦ
        'createuser',      // cryptcp: зарегистрировать пользователя на КриптоПро УЦ
        'checkreg',        // cryptcp: проверить состояние регистрации пользователя на КриптоПро УЦ
        'listtmpl',        // cryptcp: вывести на экран шаблоны, доступные пользователю КриптоПро УЦ
        'createrqst',      // cryptcp: создать запрос на сертификат и сохранить его в файле PKCS #10
        'instcert',        // cryptcp: установить сертификат из файла PKCS #7 или файла сертификата
        'createcert',      // cryptcp: создать запрос на сертификат, отправить его в ЦС
        'pendcert',        // cryptcp: проверить, не выпущен ли сертификат
        'sn',              // cryptcp: сохранить/показать серийный номер лицензии
        'nochain',         // cryptcp: не включать цепочку сертификатов
        'thumbprint',      // cryptcp: выбор сертификата по отпечатку

        'install',         // certmgr: установить сертификат
        'delete',          // certmgr: удалить сертификат
        'file'             // certmgr: установить сертификат из файла
    ];

    /**
     * Конструктор класса CryptoProBuilder.
     * Инициализирует ConsoleRunner с указанной командой.
     *
     * @param string $command Путь к исполняемому файлу (например, 'csptest', 'cryptcp').
     * По умолчанию 'csptest', если он прописан в PATH.
     */
    public function __construct(string $command = 'csptest')
    {
        $this->csp = new ConsoleRunner();
        $this->csp->setCommand($command); // csptest должно быть прописано в окружении, иначе полный путь
    }

    /**
     * Динамический вызов методов, соответствующих командам в $this->methods.
     * Позволяет удобно строить цепочки команд.
     *
     * @param string $name Имя вызываемого метода (команды).
     * @param array $arguments Аргументы, передаваемые команде.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws BadMethodCallException Если метод не поддерживается.
     */
    public function __call(string $name, array $arguments): self
    {
        if (in_array($name, $this->methods)) {
            $this->csp->addKey('-' . $name);

            // Если есть аргумент — добавь его тоже
            if (!empty($arguments)) {
                foreach ($arguments as $arg) {
                    $this->csp->addKey($arg);
                }
            }

            return $this;
        }

        throw new BadMethodCallException("Метод '$name' не поддерживается");
    }

    /**
     * Регистрирует пользовательские методы, добавляя их к существующему списку.
     *
     * @param array $customMethods Массив новых методов для регистрации.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function registerMethods(array $customMethods): self
    {
        $this->methods = array_unique(array_merge($this->methods, $customMethods));
        return $this;
    }

    /**
     * Обертка для добавления произвольного аргумента/ключа к команде.
     *
     * @param string $key Ключ или аргумент для добавления.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function addKey(string $key): self
    {
        $this->csp->addKey($key);

        return $this;
    }

    /**
     * Выводит список всех доступных контейнеров.
     *
     * @param bool $fullPath Если true, возвращает полный путь контейнера; иначе только имя.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function getContainers(bool $fullPath = true): self
    {
        $this->pattern = $fullPath ? (array)$this->patterns['containerFullPath'] : (array)$this->patterns['containerNameOnly'];

        $this->keyset()
            ->enum_cont()
            ->verifycontext()
            ->fqcn();

        return $this;
    }

    /**
     * Проверяет контейнер и подготавливает вывод результатов.
     *
     * @param string|null $container Имя/путь контейнера для проверки. Обязателен.
     * @param string|null $pass Пароль к контейнеру (опционально).
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если контейнер не указан.
     */
    public function checkContainer(?string $container = null, ?string $pass = null): self
    {
        if (!$container) {
            throw new InvalidArgumentException("Не выбран контейнер.");
        }

        $this->keyset()
            ->check()
            ->cont($container)
            ->silent();

        if ($pass) {
            $this->csp->password($pass);
        }

        return $this;
    }

    /**
     * Сменить пароль контейнера.
     *
     * @param string|null $container Имя/путь контейнера. Обязателен.
     * @param string|null $newPass Новый пароль для контейнера. Обязателен.
     * @param string|null $currentPass Текущий пароль контейнера. Обязателен.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если не указан контейнер или пароли.
     */
    public function changeContainerPass(?string $container = null, ?string $newPass = null, ?string $currentPass = null): self
    {
        if (!$container || !$newPass) {
            throw new InvalidArgumentException("Не выбран контейнер или пароль.");
        }
    
        $this->passwd()
             ->change($newPass)
             ->cont($container);
        

        if (!empty($currentPass)) {
            $this->passwd($currentPass);
        }
            

        return $this;
    }

    /**
     * Подготавливает команду для копирования контейнера.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function copyContainer(): self
    {
        $this->keycopy();

        return $this;
    }

    /**
     * Подготавливает команду для удаления контейнера.
     *
     * @param string|null $container Имя/путь контейнера для удаления. Обязателен.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если контейнер не указан.
     */
    public function deleteContainer(?string $container = null): self
    {
        if (!$container) {
            throw new InvalidArgumentException("Не выбран контейнер.");
        }

        $this->keyset()
            ->deletekeyset()
            ->container($container);

        return $this;
    }

    /**
     * Подготавливает команду для получения хэша файла.
     *
     * @param string $filePath Путь к файлу.
     * @param string $alg Алгоритм хэширования (по умолчанию 'GR3411_2012_512').
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если файл не найден.
     */
    public function hashFile(string $filePath, string $alg = 'GR3411_2012_512'): self
    {
        if (!file_exists($filePath)) {
            throw new InvalidArgumentException("Файл не найден: $filePath");
        }

        $this->pattern = $this->patterns['hashFile']['patterns'];
        $this->expectedFields = $this->patterns['hashFile']['fields'];

        $this->mk()
            ->alg($alg)
            ->addKey($filePath);

        return $this;
    }

    /**
     * Подготавливает команду для проверки хэша файла.
     *
     * @param array $files Массив из 1 или 2 элементов: [исходный_файл, опционально_хэш_или_путь_к_нему].
     * @param string $alg Алгоритм хэширования (по умолчанию 'GR3411_2012_512').
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если количество файлов некорректно, файл не найден, или формат хэша неверен.
     */
    public function verifyHash(array $files, string $alg = 'GR3411_2012_512'): self
    {
        $count = count($files);

        if ($count < 1 || $count > 2) {
            throw new InvalidArgumentException("Ожидался массив из 1 или 2 элементов: [исходный_файл, опционально_хэш_или_путь_к_нему].");
        }

        [$filePath, $hashOrPath] = [$files[0], $files[1] ?? null];

        if (!file_exists($filePath)) {
            throw new InvalidArgumentException("Файл не найден: $filePath");
        }

        $this->pattern = $this->patterns['verifyHash']['patterns'];
        $this->expectedFields = $this->patterns['verifyHash']['fields'];

        $this->addKey($filePath)
            ->alg($alg);

        if ($hashOrPath) {
            $hash = is_file($hashOrPath) ? trim(file_get_contents($hashOrPath)) : trim($hashOrPath);

            // Проверяем, что 'hashformat' в patterns - это строка, и используем её как паттерн
            if (!is_string($this->patterns['hashformat']) || !preg_match($this->patterns['hashformat'], $hash)) {
                throw new InvalidArgumentException("Неверный формат хэша или неверный путь.");
            }

            $this->addKey($hash);
        }

        return $this;
    }

    /**
     * Подготавливает команду для подписи документа.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function signDocument(): self
    {
        $this->sfsign()
            ->sign();

        return $this;
    }

    /**
     * Подготавливает команду для проверки подписи на документе.
     *
     * @param array $files Массив файлов для проверки (1 для присоединенной, 2 для отсоединенной подписи).
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если файл не найден или количество файлов некорректно.
     */
    public function verifySignature(array $files): self
    {
        foreach ($files as $filePath) {
            if (!file_exists($filePath)) {
                throw new InvalidArgumentException("Файл не найден: $filePath");
            }
        }

        $this->verify();

        // Паттерн для извлечения информации о подписанте
        // Убедитесь, что 'signatureOwner' - это строка-паттерн
        $this->pattern = (array)$this->patterns['signatureOwner'];

        // Проверка, сколько файлов передано
        if (count($files) === 1) {
            // Присоединенная подпись - 1 файл
            $this->attached()
                 ->nochain()
                 ->addKey(...$files); // Добавляем файлы как аргументы
        } elseif (count($files) === 2) {
            // Отсоединенная подпись - 2 файла
            $this->detached()
                 ->nochain()
                 ->addKey(implode(' ', $files)); // Добавляем файлы как аргументы
        } else {
            // Обработка ошибки, если файлов больше двух или меньше одного
            throw new InvalidArgumentException("Неверное количество файлов во входном массиве. Ожидается 1 или 2 файла.");
        }

        return $this;
    }

    /**
     * Подготавливает команду для шифрования документа.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function encryptDocument(): self
    {
        $this->encr();

        return $this;
    }

    /**
     * Подготавливает команду для расшифровки файла.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function decryptDocument(): self
    {
        $this->decr();

        return $this;
    }

    /**
     * Подготавливает команду для установки сертификата из файла или контейнера.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function certificatInstall(): self
    {
        // Использование 'instcert' из методов cryptcp
        $this->install();

        return $this;
    }

    /**
     * Подготавливает команду для получения списка сертификатов.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function getCertificates(): self
    {
        $this->pattern = $this->patterns['certificates']['patterns'];
        $this->expectedFields = $this->patterns['certificates']['fields'];
        $this->structureMatches = true; // Структурировать плоский вывод

        $this->list();

        return $this;
    }

    /**
     * Подготавливает команду для получения сертификата по отпечатку (или другим параметрам списка).
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function getCertificateByTp(): self
    {
        $this->pattern = $this->patterns['certificates']['patterns'];
        $this->expectedFields = $this->patterns['certificates']['fields'];
        $this->structureMatches = false; // Для одного сертификата не нужна структура

        $this->list();

        return $this;
    }

    /**
     * Подготавливает команду для удаления сертификата.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function deleteCertificate(): self
    {
        // Использование 'delcert' из методов cryptcp
        $this->delete();

        return $this;
    }

    /**
     * Устанавливает кодировку для ConsoleRunner, если командная строка имеет проблемы с UTF-8 и кириллицей.
     *
     * @param string $code Кодировка (например, 'CP866').
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function encoding(string $code): self
    {
        $this->csp->encoding($code);

        return $this;
    }

    /**
     * Устанавливает флаг для ConsoleRunner для возврата к исходной кодировке,
     * если вывод делается в ту же консоль.
     *
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function decoding(): self
    {
        $this->csp->decoding();

        return $this;
    }

    /**
     * Устанавливает паттерны и ожидаемые поля для парсинга вывода из массива $patterns.
     *
     * @param string|null $patternName Имя паттерна из `$this->patterns`.
     * @param array|null $patternFields Массив с именами ключей для 'fields' и 'patterns' (например, ['fields', 'patterns']), если паттерн вложенный.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     * @throws InvalidArgumentException Если паттерн не найден или структура `patternFields` неверна.
     */
    public function usePattern(?string $patternName = null, ?array $patternFields = null): self
    {
        if ($patternName === null) {
            $this->pattern = null;
            $this->expectedFields = null;
            $this->structureMatches = false;
            return $this;
        }

        if (!isset($this->patterns[$patternName])) {
            throw new InvalidArgumentException("Паттерн '{$patternName}' не найден.");
        }

        $patternData = $this->patterns[$patternName];

        if (is_array($patternData) && $patternFields !== null && count($patternFields) === 2) {
            [$fieldsKey, $patternsKey] = $patternFields;

            if (!isset($patternData[$patternsKey]) || !isset($patternData[$fieldsKey])) {
                throw new InvalidArgumentException("Массив с полями или паттернами для '{$patternName}' не найден по указанным ключам.");
            }

            $this->pattern = (array)$patternData[$patternsKey];
            $this->expectedFields = (array)$patternData[$fieldsKey];
        } else {
            // Если паттерн не является вложенным массивом с 'fields' и 'patterns'
            $this->pattern = is_array($patternData) ? $patternData : [$patternData];
            $this->expectedFields = null; // Сбрасываем, так как нет явных полей
        }

        return $this;
    }

    /**
     * Устанавливает флаг для структурирования выходных данных.
     *
     * @param bool $structure True, если данные должны быть структурированы, false иначе.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function useStructure(): self
    {
        $this->structureMatches = true;
        return $this;
    }

    /**
     * Добавляет пользовательские паттерны регулярных выражений к исходному массиву $patterns.
     *
     * @param array $patterns Массив паттернов для добавления.
     * @return self Возвращает текущий инстанс для цепочки вызовов.
     */
    public function addPatterns(array $patterns): self
    {
        $this->patterns = array_merge($this->patterns, $patterns);
        return $this;
    }

    /**
     * Структурирует плоский массив совпадений в ассоциативный массив на основе заданных полей.
     *
     * @param array $matches Плоский массив совпадений.
     * @param array $fields Массив имен полей для структурирования.
     * @return array Массив структурированных данных.
     * @throws RuntimeException Если количество совпадений не соответствует структуре.
     */
    private function structureMatches(array $matches, array $fields): array
    {
        $chunkSize = count($fields);
        if ($chunkSize === 0) {
            return []; // Невозможно структурировать без полей
        }

        // Проверяем, что количество совпадений кратно размеру чанка
        if (count($matches) % $chunkSize !== 0) {
             throw new RuntimeException("Несоответствие количества найденных совпадений ({count($matches)}) и ожидаемых полей ({$chunkSize}) для структурирования.");
        }

        $structuredData = [];
        foreach (array_chunk($matches, $chunkSize) as $chunk) {
            $structuredData[] = array_combine($fields, $chunk);
        }

        return $structuredData;
    }

    /**
     * Выводит сгенерированную строку команды и завершает выполнение скрипта.
     * Полезно для отладки.
     *
     * @return null
     */
    public function printBuilderString(): ?string
    {
        exit($this->csp->getCommand());
    }

    /**
     * Запускает выполнение команды и обрабатывает результат.
     *
     * @return array Возвращает структурированный результат в случае успеха.
     * @throws RuntimeException В случае ошибки выполнения команды или парсинга.
     */
    public function run(): array
    {
        if ($this->csp->run()) {
            return $this->success();
        }

        return $this->throwError();
    }


    /**
     * Обрабатывает успешное выполнение команды, парсит вывод и возвращает его.
     *
     * @return array Обработанный вывод.
     * @throws RuntimeException Если паттерны заданы, но данные не найдены, или неверное количество полей.
     */
    private function success(): array
    {
        if ($this->pattern === null) {
            return ['status' => 'успешно'];
        }

        $matches = $this->csp->getMatches($this->pattern);

        if (empty($matches)) {
            // Если паттерны заданы, но ничего не найдено
            throw new RuntimeException("Паттерны заданы, но данные не найдены в выводе.");
        }

        // Если ожидаемые поля заданы и количество совпадений соответствует количеству полей (один набор данных)
        if ($this->expectedFields !== null && count($matches) === count($this->expectedFields)) {
            return array_combine($this->expectedFields, $matches);
        }

        // Если включено структурирование и есть ожидаемые поля
        if ($this->structureMatches && $this->expectedFields !== null) {
            return $this->structureMatches($matches, $this->expectedFields);
        }

        // Если не удалось применить структурирование/комбинацию, возвращаем сырые совпадения
        return $matches;
    }

    /**
     * Обрабатывает ошибку выполнения команды, извлекая код ошибки.
     *
     * @return never
     * @throws RuntimeException Всегда выбрасывает исключение с кодом ошибки.
     */
    private function throwError(): never
    {
        // Поиск ошибки в формате [ErrorCode: 0x...]
        $pattern = '/\[ErrorCode:\s*(0x[0-9A-Fa-f]+)\]/';
        $matches = $this->csp->getMatches($pattern);

        if (empty($matches) || !isset($matches[0])) {
            throw new RuntimeException("Ошибка выполнения: Не удалось извлечь код ошибки.");
        }

        throw new RuntimeException("Ошибка выполнения, код: " . $matches[0]);
    }

}