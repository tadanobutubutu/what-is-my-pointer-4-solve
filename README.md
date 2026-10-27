> [!IMPORTANT]
> **Solved with Gemini in Colab**
>
> この問題は Google の AI コーディングアシスタント **Gemini in Colab** を活用して解決されました。

> [!NOTE]
> この Writeup は AI により自動生成されています。 本ドキュメントは、AI アシスタントを用いて作成された Writeup です。記載内容は解法の一例であり、内容の正確性については十分にご確認の上ご利用ください。

# what is my pointer 4

## 概要
*   **カテゴリー**: Pwn
*   **トピック**: malloc
*   **難易度**: Hard
*   **問題リンク**: [what is my pointer 4 - Daily AlpacaHack](https://alpacahack.com/daily/challenges/what-is-my-pointer-4)

## 使用ツール
*   **Python 3**: 解法スクリプトの実装
*   **socket / struct / re**: サーバーとの通信、リトルエンディアンの復元、出力の抽出（いずれも Python 標準ライブラリ）

## 問題の分析
本問題は、**Daily AlpacaHack** の Pwn 問題です。配布ファイルは次の通りです。

| ファイル | 内容 |
| :--- | :--- |
| `chal.c` | 本体のソースコード |
| `chal` | `chal.c` をコンパイルした実行ファイル |
| `Dockerfile` | `chal` を `xinetd` で TCP 公開するコンテナ定義 |
| `compose.yml` | コンテナを起動する設定 |

`chal.c` の中身は次の通りです。

```c
int main(void) {
    printf("[DEBUG] flag: %p\n", getenv("FLAG"));

    puts("part1: alloc");
    size_t size;
    printf("size> ");
    scanf("%ld%*c", &size);
    unsigned long *item = malloc(size);

    puts("part2: read");
    printf("index> ");
    off_t index;
    scanf("%ld%*c", &index);
    printf("0x%lx\n", item[index]);

    puts("bye!!");
}
```

やり取りは「サイズを 1 つ入力して `malloc` し、インデックスを 1 つ入力してその要素を読む」だけです。問題のタイトル通り、鍵は `item` という **ポインタがどこを指すか** です。

```mermaid
sequenceDiagram
    participant S as サーバー (chal)
    participant A as 解く人
    S->>A: [DEBUG] flag: アドレスを表示
    S->>A: size> 
    A->>S: サイズを入力
    S->>S: item = malloc(size)
    S->>A: index> 
    A->>S: インデックスを入力
    S->>A: item[index] の値を 16 進で表示
```

## 脆弱性の詳細

### 1. フラグのアドレスが丸見え
プログラムは起動直後に `getenv("FLAG")` の戻り値、つまり **環境変数 `FLAG` が置かれているアドレス** を `%p` で表示します。読みたいデータがメモリ上のどこにあるかが、毎回そのまま教えられます。

### 2. `malloc` を失敗させて `item` を NULL にする
`size` は `size_t`（符号なし 64bit）なのに、`scanf` の変換指定は `%ld`（本来は `long *` 用）なので、型としては不一致です。ただし入力が `-1` のとき、実務上はビットパターンが全ビット 1（`0xffffffffffffffff` = `SIZE_MAX`）として `size_t` に載るため、結果として巨大なサイズ要求になります。この値はアロケータの上限チェックに引っかかり、確保に失敗して `malloc` は `NULL`（= 0）を返します。

```math
\texttt{size} = \texttt{-1} \;\Rightarrow\; \texttt{SIZE\_MAX} \;\Rightarrow\; \texttt{item} = \texttt{malloc(size)} = 0
```

### 3. 任意アドレス読み取りへ
`item` が 0 になると、`item[index]` は次の式のアドレスを参照します。`item` は `unsigned long *`（1 要素 8 バイト）なので、インデックスは 8 倍されます。

```math
\texttt{item[index]} = *(\texttt{item} + \texttt{index}) = *(\texttt{index} \times 8)
```

読めるのは **8 バイト境界のアドレス** に限られ、さらに `index` は `off_t`（符号付き 64bit）なので、その符号付き範囲に収まる必要があります。読みたいアドレスを $`A`$ とすると、必要なインデックスは次の通りです。

```math
\texttt{index} = \left\lfloor \frac{A}{8} \right\rfloor
```

フラグのアドレスは手順 1 で分かっているので、そこから 8 バイトずつ読み出せばフラグ全体を復元できます。

> [!NOTE]
> サーバーは 1 接続につき「1 回の読み取り」しかさせてくれません。そのため、接続をやり直しながら 8 バイトずつずらして読み、フラグをつなぎ合わせます。本解法の `solve.py` は $`i = 0..7`$ の 8 回（最大 64 バイト）まで取得します。Daily AlpacaHack のフラグ長なら足りる前提です。

### 4. アドレスは接続のたびに変わる（ASLR）
環境変数はスタック上に置かれ、アドレス空間配置のランダム化（**ASLR**）によって接続ごとに位置が変わります。したがって、過去の接続で得たアドレスを使い回すことはできません。各接続で表示される `[DEBUG] flag:` の値を **その接続内で** 読み、そのアドレスを基準にインデックスを計算する必要があります。

## 攻撃フロー
```mermaid
flowchart TD
    A["i = 0..7 で接続を繰り返す"] --> B["DEBUG flag からアドレス addr を読む"]
    B --> C["size に -1 を送る → item = NULL"]
    C --> D["index = addr // 8 + i を送る"]
    D --> E["返ってきた 8 バイトを i 番目のブロックとして保存"]
    E --> F{"8 ブロック揃った？"}
    F -- No --> A
    F -- Yes --> G["全ブロックを連結し NULL までを取り出す"]
    G --> H["Flag 獲得"]
```

## 補足
読み取り粒度が 8 バイト固定でも、フラグのアドレスが分かっているため計算はずれません。$`i`$ 番目の接続で読むアドレスは $`A_i = A_i' - (A_i' \bmod 8) + 8i`$ のようにそのつど基準化され、保存先オフセットも同じ基準で求めます。ここで $`A_i'`$ は $`i`$ 番目の接続で表示されたフラグアドレスです。各接続で基準を取り直すことで、ASLR で絶対位置が変わっても相対位置（フラグ先頭からの距離）は常に正しく対応します。保存時も $`0 \le \texttt{off} < 64`$ の範囲だけを採用しており、取得上限は 64 バイトです。

> [!WARNING]
> 「確保サイズ」や「インデックス」をユーザー入力のまま使い、確保の成否もチェックしないと、`NULL` 参照からの任意アドレス読み取りにつながります。`malloc` の戻り値は必ず検査し、インデックスには範囲チェックを入れるべきです。

## 用語解説
*   **`malloc` の失敗**: 要求サイズがアロケータの上限を超えるなどして確保できないとき、`malloc` は `NULL`（0）を返します。本問では `SIZE_MAX` を渡して上限チェックで弾かせ、意図的に `item` を 0 にします。
*   **ASLR（Address Space Layout Randomization）**: スタックやライブラリの配置アドレスを起動ごとにランダム化する保護機構です。本問ではアドレスが毎回表示されるため、保護になっていません。
*   **`off_t` / `size_t`**: それぞれ符号付き・符号なしの整数型です。`scanf("%ld")` は本来 `long *` 用で `size_t` への読み込みは型不一致ですが、`-1` のビットパターンが実務上 `SIZE_MAX` と一致するため巨大サイズ化が起きます。`off_t` の符号付き範囲は、負インデックスや読めるアドレス範囲の上限にも効いてきます。
*   **リトルエンディアン**: 8 バイトの値を下位バイトから並べる方式です。`struct.pack("<Q", val)` でバイト列に戻してから文字として連結します。

## 解決スクリプト
[solve.py を参照してください](./solve.py)

```bash
python3 solve.py <HOST> <PORT>
```

接続先の HOST と PORT は、問題ページでインスタンスを起動して確認してください。
