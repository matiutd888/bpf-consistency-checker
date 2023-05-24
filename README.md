# BPF consistency checker
Patch to `6.2.1` Linux kernel that introduces a new type of eBPF program, that can be used to calculate checksums on file writes and validate them using dedicated syscalls.
Written for _Advanced topics in operating systems_ University course.

Below you can find a content of _README.md_ that was submitted as a part of the solution.

#### Krótki opis rozwiązania

Wzbogaciłem strukturę file (`struct file`) o  
1. Listę checksum (kernelowa linked lista). Lista jest chroniona rwlockiem.
2. Licznik checksum do policzenia przy następnych operacjach zapisu. Licznik ten jest atomowy, choć chyba nie ma takiej potrzeby.

Lista inicjowana jest w `__alloc_file()` , natomiast zwalniana jest w `file_free()`.


Używam domyślnego typu `bpf_tramp_prog_type`, mianowicie `BPF_TRAMP_REPLACE` by podpiąć program bpfowe w odpowiednie miejsca.
Punkty podpięcia wywołuję w

1. `system_openat2`  dla `checker_decide`
2. `vfs_write`, `vfs_writev` dla `checker_calculate`. Robię to jako ostatnią operację, jeśli zapis się udał (wartość zwracana przez funkcje, odpowiadająca liczbie zapisanych bajtów jest większa od  0)

Funkcja `copy_to_buffer` zaimplementowana została z użyciem makra `container_of`, które pomaga wydobyć adres struktury, której polem jest `checker_ctx`. Zapis do bufora odbywa się niestety za pomocą czytania do pliku, tj używam `kernel_read`. Zapewne bardziej optymalnym mogło byc czytanie z buforów dostępnych w pamięci przy `write` i `writev`, jednak nie starczyło mi czasu na sprawdzenie tego.

#### Podjęte decyzje

* Jeżeli `checker_decide` zwróci wartość mniejszą od zera, uznaję to jako błąd i nie resetuję licznika w strukturze file
* Jeżeli z licznika wynika, że `checker_calculate` powinno byc wywołane, a nie został załadowany żaden program (czyli wywoła się domyślna, kernelowa implementacja `checker_decide`) , to kończę syscalla związanego z zapisem z błędem `EINVAL`. Z tym samym błędem kończę te syscalle, jeżeli `kmalloc` nie zakończy się powodzeniem (mimo, że `-ENOMEM` jest prawdopodobnie bardziej odpowiedni; Wydawało mi się, że z polecenia wynika, że błędy związane z `checker_calculate` powinny kończyć się zwracaniem `-EINVAL`). Nie traktuję ujemnych wartości zwracanych przez `checker_calculate` jako błąd.
* Spotkałem się z interpretacją mówiącą, że w przypadku `writev`, funkcja `checker_calculate` powinna być wołana przy każdym zapisie do pliku z buforu będącego elementem na tablicy `iovec`, bo to te właśnie operacje są "operacjami zapisu". Ja jednak uznałem całe `writev` za pojedynczą operację zapisu i `checker_calculate` wywołuję tylko raz, na samym końcu.
* W przypadku `int get_checksum(int fd, size_t size, off_t offset, int * checksum)` zwracam ostatnio dodaną checksumę spełniającą warunki.

#### Uwagi do rozwiązania
W rozwiązaniu zostały miejsca  w którym ciało którejś z gałęzi if/else jest puste. Są to pozostałości po `printk` , których dodałem dużo w kodzie podczas pisania rozwiazania, a które musiałem usunąć by zrobić patcha z rozwiązaniem. Nie należy owymi pustymi gałęziami się przejmować :) .
