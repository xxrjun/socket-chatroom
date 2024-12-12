PROMPT_TEMPLATE = """請協助優化以下提供的 Python 程式碼。請針對以下幾個方面進行改進：

1. **可讀性**：重構程式碼以提高可讀性，包括改善變數和函數命名、增加適當的註解以及整理程式碼結構。
2. **性能**：分析程式碼的性能瓶頸，提出優化建議，並實施性能改進。
3. **可維護性**：確保程式碼遵循最佳實踐和設計模式，提高其可維護性和擴展性。
4. **錯誤處理**：增強程式碼的錯誤處理機制，確保其穩定性和可靠性。
5. **安全性**：檢查並修復可能的安全漏洞，如資安弱點、資料加密處理等。

請在優化後提供修改過的程式碼，並簡要說明所做的主要改進。

以下是需要優化的專案架構：
```
{project_tree}
```

以下是需要優化的程式碼：
```
{combined_code}
```"""

with open("project_tree.txt", "r") as f:
    project_tree = f.read()

with open("combined_code.txt", "r") as f:
    combined_code = f.read()


prompt = PROMPT_TEMPLATE.format(project_tree=project_tree, combined_code=combined_code)

with open("prompt.txt", "w") as f:
    f.write(prompt)
