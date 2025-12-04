use docx_rs::{DocumentChild, ParagraphChild, RunChild};

/// Рекурсивно извлекает текст из документа

pub fn extract_text_from_docx(docx: &docx_rs::Docx) -> String {
    let mut result = String::new();

    for element in &docx.document.children {
        match element {
            DocumentChild::Paragraph(p) => {
                result.push_str(&extract_text_from_paragraph(p));

                result.push('\n');
            }
            DocumentChild::Table(t) => {
                for row in &t.rows {
                    if let docx_rs::TableChild::TableRow(row) = row {
                        // Теперь 'row' - это TableRow, и ячейки лежат в row.cells
                        for cell in &row.cells {
                            if let docx_rs::TableRowChild::TableCell(cell) = cell {
                                for content in &cell.children {
                                    // Внутри ячейки таблицы
                                    if let docx_rs::TableCellContent::Paragraph(p) = content {
                                        result.push_str(&extract_text_from_paragraph(p));

                                        result.push(' ');
                                    }
                                }
                            }
                        }

                        result.push('\n'); // Новая строка после каждой строки таблицы
                    }
                }
            }
            _ => {}
        }
    }

    result
}

/// Извлекает текст из конкретного параграфа

pub fn extract_text_from_paragraph(p: &docx_rs::Paragraph) -> String {
    let mut text = String::new();

    for child in &p.children {
        if let ParagraphChild::Run(run) = child {
            for run_child in &run.children {
                if let RunChild::Text(t) = run_child {
                    text.push_str(&t.text);
                }
            }
        }
    }

    text
}
