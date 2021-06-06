package invoice_item

import (
	"github.com/Nistagram-Organization/agent-shared/src/model/invoice_item"
	"github.com/Nistagram-Organization/agent-shared/src/utils/rest_error"
)

type InvoiceItemRepository interface {
	GetByProduct(uint) (*invoice_item.InvoiceItem, rest_error.RestErr)
}
