# CryptoProBuilder

**CryptoProBuilder** — это PHP-библиотека, предоставляющая удобный интерфейс для взаимодействия с утилитами КриптоПро CSP (csptest, cryptcp, cpverify, certmgr). Она позволяет программно выполнять криптографические операции, такие как подписание, шифрование, хеширование, управление контейнерами и сертификатами, а также парсить вывод консольных утилит для получения структурированных результатов.


## Особенности

- **Текучий интерфейс (Fluent Interface)**: Выполняйте команды в интуитивно понятном, читаемом стиле.
  
- **Динамические методы**: Автоматически вызывайте команды csptest, cryptcp, cpverify, certmgr как методы класса.

- **Парсинг вывода**: Используйте предопределенные или пользовательские регулярные выражения для извлечения данных из стандартного вывода утилит.

- **Обработка ошибок**: Автоматическая идентификация и обработка ошибок выполнения команд с кодами ошибок КриптоПро.

- **Управление кодировкой**: Возможность настройки кодировки для корректной работы с кириллицей в консоли.

---

## Требования

- **PHP 8.0 или выше.**

- **Установленный КриптоПро CSP** - включая консольные утилиты csptest, cryptcp, cpverify, certmgr.

- **mikhailovlab/php-fluent-console** - данная библиотека используется для запуска консольных команд и является зависимостью.


## Установка

```cmd/bash
composer require mikhailovlab/crypto-pro-builder
```

- **Важное замечание:** Убедитесь, что исполняемые файлы КриптоПро (например, csptest, cryptcp, cpverify и certmgr - обычно идут в комплекте с дистрибутивом КриптоПро) доступны в переменной окружения PATH вашего сервера или укажите полный путь к ним при инициализации класса CryptoPro.

## Обзор методов и возможностей
Библиотека CryptoProBuilder предоставляет набор интуитивно понятных методов, которые соответствуют основным операциям консольных утилит КриптоПро. Благодаря текучему интерфейсу, вы можете легко строить цепочки команд, делая ваш код читаемым и лаконичным.

### Свойства 
Вам необязательно знать их все, но это может быть полезно на случай разработки своих собственных методов.

Инстанс ConsoleRunner для выполнения команд.
```php 
protected ConsoleRunner $csp;
```

Коллекция предопределенных паттернов для парсинга вывода команд.
```php 
protected array $patterns;
```

Текущий активный паттерн(ы) для парсинга вывода.
```php 
protected ?array $pattern;
```

Ожидаемые поля для структурированного вывода.
```php 
protected ?array $expectedFields;
```

Флаг, указывающий, нужно ли структурировать выходные данные.
```php 
protected bool $structureMatches;
```

Массив доступных команд/методов, которые могут быть вызваны динамически.
```php 
protected array $methods;
```

### Методы
Инициализирует ConsoleRunner с указанной командой. По умолчанию установлен 'csptest'.
```php 
public function __construct(string $command = 'csptest')
```

Динамический вызов методов, соответствующих командам в $this->methods.
```php 
public function __call(string $name, array $arguments): self
```

Регистрирует пользовательские методы, добавляя их к существующему списку. 
```php
public function registerMethods(array $customMethods): self
```

Обертка для добавления произвольного аргумента/ключа к команде.
```php
public function addKey(string $key): self
```

Выводит список всех доступных контейнеров.
```php
public function getContainers(bool $fullPath = true): self
```

Проверяет целостность контейнера и подготавливает вывод результатов.
```php
public function checkContainer(?string $container = null, ?string $pass = null): self
```

Меняет пароль контейнера.
```php
public function changeContainerPass(?string $container = null, ?string $newPass = null, ?string $currentPass = null): self
```

Копирует контейнер.
```php
public function copyContainer(): self
```

Удаляет контейнер.
```php
public function deleteContainer(?string $container = null): self
```

Возвращает хэш файла, для подписания, например.
```php
public function hashFile(string $filePath, string $alg = 'GR3411_2012_512'): self
```

Проверяет хэш.
```php
public function verifyHash(array $files, string $alg = 'GR3411_2012_512'): self
```

Подписывает файл.
```php
public function signDocument(): self
```

Проверяет подпись файла.
```php
public function verifySignature(array $files): self
```

Шифрует файл.
```php
public function encryptDocument(): self
```

Расшифровывает файл.
```php
public function decryptDocument(): self
```

Устанавливает сертификат из файла или контейнера.
```php
public function certificatInstall(): self
```

Выводит список сертификатов.
```php
public function getCertificates(): self
```

Выводит сертификат по отпечатку.
```php
public function getCertificateByTp(): self
```

Удаляет сертификат.
```php
public function deleteCertificate(): self
```

Пробрасывает кодировку в ConsoleRunner (Для парсинга кириллицы).
```php
public function encoding(string $code): self
```

Устанавливает флаг для ConsoleRunner для возврата к исходной кодировке (если вывод осуществляется в консоль).
```php
public function decoding(): self
```

Устанавливает паттерны и ожидаемые поля для парсинга вывода из массива $patterns.
```php
public function usePattern(?string $patternName = null, ?array $patternFields = null): self
```

Устанавливает флаг для структурирования выходных данных.
```php
public function useStructure(): self
```

Добавляет пользовательские паттерны регулярных выражений к исходному массиву $patterns.
```php
public function addPatterns(array $patterns): self
```

Структурирует плоский массив совпадений в ассоциативный массив на основе заданных полей.
```php
private function structureMatches(array $matches, array $fields): array
```

Выводит сгенерированную строку команды и завершает выполнение скрипта.
```php
public function printBuilderString(): ?string
```

Запускает выполнение команды и обрабатывает результат.
```php
public function run(): array
```

Обрабатывает успешное выполнение команды, парсит вывод и возвращает его.
```php
private function success(): array
```

Обрабатывает ошибку выполнения команды, извлекая код ошибки.
```php
private function throwError(): never
```


## Примеры использования
Для работы с библиотекой нам необязательно погружаться в документацию, мы можем использовать шаблонные решения.

По стандартной схеме, тестировать будем с использованием фреймворка Laravel 11, на операционной системе windows 10. Вы можете использовать любую другую конфигурацию (фреймворк, ОС и т.д.), главное — обеспечить корректную установку и доступность утилит КриптоПро.

### Получить список контейнеров 
```php
try{
    dd(new CryptoPro()
        ->getContainers()
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:6 [▼ // app\Http\Controllers\TestController.php:23
  0 => "\\.\FAT12_H\d58fe6c13-d917-2a53-8e9c-8c4b8158220"
  1 => "\\.\FAT12_H\c3965c1c-56de-4ed2-a6bd-fcfe1f47f77f"
  2 => "\\.\FAT12_H\469233b1-9ccd-4a74-9264-a9b4837ad3b5"
  3 => "\\.\FAT12_H\e00b1f31-ecb7-4827-9c5b-f1460c682261"
  4 => "\\.\FAT12_H\015b6fa9-e71d-4240-be9f-0462b40e0042"
  5 => "\\.\FAT12_H\8ac2691d-c4d5-457e-8d47-3a52e5a2691a"
]
```

### Протестировать контейнер
```php
try{
    dd(new CryptoPro()
        ->checkContainer($container)
        //->password($password) пароль, если требуется
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:23
  "status" => "успешно"
]
```

### Изменить пароль контейнера
```php
try{
    dd(new CryptoPro()
        ->changeContainerPass($container, currentPass: '', newPass: '1234')
	->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:25
  "status" => "успешно"
]
```

### Скопировать контейнер
```php
try{
    dd(new CryptoPro()
        ->copyContainer()
        ->contsrc($container1) //входной контейнер
        ->contdest($container2) //выходной контейнер
        ->pinsrc('1234') //пароль входного контейнера, если требуется
        //->pindest() пароль выходного контейнера, если требуется
        ->silent() //не выводить окно с вводом пароля
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:25
  "status" => "успешно"
]
```

### Удалить контейнер
```php
try{
    dd(new CryptoPro()
        ->deleteContainer($container)
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:25
  "status" => "успешно"
]
```

### Получить хэш файла
```php
try{
    dd(new CryptoPro('cpverify') //либо полный путь
        ->hashFile('H:\csp\123.txt')
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:25
  "hash" => "275BF35756C49E7A35810893777AC4F5E0E56D3D24A259502C56F2CFA5048014A7496908CDB177C3B939E5D38CC51299E5D364226C0B8BEB80030CE86F6A1762"
]
```

### Проверить хэш
```php
try{
    dd(new CryptoPro('cpverify')
        ->verifyHash(['H:\csp\123.txt', $hash]) //второй элемент хэш строка или путь к файлу
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:25
  "status" => "File 'H:\csp\123.txt' has been verified"
]
```

### Подписать документ
```php
try{
    dd(new CryptoPro()
        ->signDocument()
        ->in('H:\csp\123.txt')
        ->out('H:\csp\123.txt.sig')
        ->password('1234') //пароль, если требуется 
        ->my('00dad6c045c2ec4a01f20441daf2d8dd999aaf07') // Сертификат 
        ->addsigtime() //добавить время подписи, если требуется
        ->base64() // base64, если требуется
        ->detached() //отсоединенная подпись, если требуется
        ->add() //добавить сертификат, если требуется
        ->silent() //не выводить окно с вводом пароля
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:25
  "status" => "успешно"
]
```

### Проверить подпись
```php
$array = [
    'H:\csp\123.txt',
    'H:\csp\123.txt.sig' //для присоединенной подписи указываем только 1 файл
];

try{
    dd(new CryptoPro("cryptcp")
        ->encoding('866') // windows консоль выдаст кириллицу в 866
        ->verifySignature($array)
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:31
  0 => "RU, Москва, Сидоров Иван Иванович, sidorov@mail.ru"
]
```

### Зашифровать файл
```php
try{
    dd(new CryptoPro("cryptcp")
        ->encryptDocument()
        ->thumbprint('00dad6c045c2ec4a01f20441daf2d8dd999aaf07')
        ->addKey('H:\csp\123.txt')
        ->addKey('H:\csp\123.txt.enc')
        ->silent()
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:26
  "status" => "успешно"
]
```

### Расшифровать файл
```php
try{
    dd(new CryptoPro("cryptcp")
        ->decryptDocument()
        ->thumbprint('00dad6c045c2ec4a01f20441daf2d8dd999aaf07')
        ->pin(1234)
        ->addKey('H:\csp\123.txt.enc')
        ->addKey('H:\csp\123decr.txt')
        ->silent()
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:26
  "status" => "успешно"
]
```

### Установить сертификат
```php
try{
    dd(new CryptoPro("certmgr.exe") //не путать со встроенной windows утилитой 
        ->certificatInstall()
        ->file('H:\csp\Cert.cer') //установить из файла
        //->cont($container) //установить из контейнера
        ->store('uMy')
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:1 [▼ // app\Http\Controllers\TestController.php:26
  "status" => "успешно"
]
```

### Получить список сертификатов
```php
try{
    dd(new CryptoPro("certmgr.exe") //не путать со встроенной windows утилитой 
        ->getCertificates()
        ->encoding('866') // Windows консоль выдаст кириллицу в 866 
        ->store('uMy')
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:12 [▼ // app\Http\Controllers\TestController.php:26
  0 => array:5 [▼
   "subject" => "Сидоров Иван Иванович"
   "serialNumber" => "0x7C001F6C9ED2E51F47F4CB4020000D001F6C9E"
   "sha1" => "00dad6c045c2ec4a01f20441daf2d8dd999aaf07"
   "issued" => "30/05/2025  01:19:45 UTC"
   "expires" => "04/07/2025  10:36:28 UTC"
  ]
  1 => array:5 [▶]
  2 => array:5 [▶]
  3 => array:5 [▶]
  4 => array:5 [▶]
  5 => array:5 [▶]
  6 => array:5 [▶]
  7 => array:5 [▶]
  8 => array:5 [▶]
  9 => array:5 [▶]
  10 => array:5 [▶]
  11 => array:5 [▶]
]
```

### Получить сертификат по отпечатку
```php
try{
    dd(new CryptoPro("certmgr.exe") //не путать со встроенной windows утилитой 
        ->getCertificateByTp()
        ->encoding('866')
        ->store('uMy')
        ->thumbprint('00dad6c045c2ec4a01f20441daf2d8dd999aaf07')
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```

```php
array:5 [▼ // app\Http\Controllers\TestController.php:26
  "subject" => "Сидоров Иван Иванович"
  "serialNumber" => "0x7C001F6C9ED2E51F47F4CB4020000D001F6C9E"
  "sha1" => "00dad6c045c2ec4a01f20441daf2d8dd999aaf07"
  "issued" => "30/05/2025  01:19:45 UTC"
  "expires" => "04/07/2025  10:36:28 UTC"
]
```

### Удалить сертификат
```php
try{
    dd(new CryptoPro("certmgr.exe") //не путать со встроенной windows утилитой 
        ->deleteCertificate()
        ->store('uMy')
        ->thumbprint('00dad6c045c2ec4a01f20441daf2d8dd999aaf07')
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```
```php
array:1 [▼ // app\Http\Controllers\TestController.php:26
  "status" => "успешно"
]
```

## Дополнительные методы, которые пригодятся для построения кастомных методов.
```php
try{
    dd(new CryptoPro()
        ->registerMethods(['install', 'delete']) //зарегистрировать дополнительные методы
        ->addKey("-nochain") //пробросить кастомный аргумент или ключ
        ->encoding('866') //добавить кодировку, например из 866 в UTF-8 (для кириллицы в windows)
        ->decoding() //вернуть исходную кодировку, если отдаем вывод в консоль 
        ->addPatterns(['patternname' => 'regexp']) //добавить кастомные паттерны для парсинга 
        ->usePattern("patternname") //использовать паттерн для парсинга 
        ->run()
    );
    
}catch (Exception $e){
    dd($e->getMessage());
}
```


