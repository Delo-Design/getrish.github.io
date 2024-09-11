# getrish.github.io
Скрипт, для начала установки RISH на новый сервер

Проверяет версию ОС и устанавливает необходимый минимум для начала установки RISH

Команда начала установки:

    curl -L get.rish.su | sh && /root/rish/ri.sh

Если у вас блокируются сервера РФ, то вот эта команда:

    curl -L getrish.sovmart.com | sh && /root/rish/ri.sh

Если на сервере не окажется установленной команды curl – ее можно установить с помощью 

    dnf install curl
    
Сайт RISH https://rish.su/

Ссылка на гитхаб RISH https://github.com/Delo-Design/rish
