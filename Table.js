import React from 'react'
import { useEffect, useRef, useState }  from 'react'
import styled from 'styled-components'
import { useTable,usePagination, useRowSelect } from 'react-table'


export const tableColumnConfig={
    'basic':[
        {
 
 
 
          Header: 'Name',
          columns: [
            {
              Header: 'First Name',
              accessor: 'firstName',
            },
            {
              Header: 'Last Name',
              accessor: 'lastName',
            },
          ],
        },
        {
          Header: 'Current Info',
          columns: [
            {
              Header: 'Visits',
              accessor: 'visits',
            },
            {
              Header: 'Status',
              accessor: 'status',
            },
            {
              Header: 'User ID',
              accessor: 'userId',
            },
            {
               Header: 'City',
               accessor: 'city',
            }
          ],
        },
      ],
    'instanceTable':[
        {
          Header: 'Basic Information',
          columns: [
            {
              Header: 'User ID',
              accessor: 'userId',
            },
            {
              Header: 'Instance ID',
              accessor: 'instanceId',
            },
            {
                Header: 'Instance IP',
                accessor: 'instanceIp',
              },
              {
                Header: 'Public DNS',
                accessor: 'publicDnsName',
              },
             
            {
                Header: 'Region',
                accessor: 'region',
              },
            {
                Header: 'Zone',
                accessor: 'zone',
              },
          ],
        },
        {
          Header: 'Metric',
          columns: [
            {
              Header: 'Launch Time',
              accessor: 'launchtime',
            },
            {
              Header: 'CPUUtilization',
              accessor: 'cpuUtilization',
            },
           
            {
              Header: 'Instance State',
              accessor: 'status',
            },
            {
              Header: 'Instance Status',
              accessor: 'instanceStatus',
            },
            {
              Header: 'System Status',
              accessor: 'systemStatus',
            },
            {
              Header: 'Network In',
              accessor: 'networkIn',
            },
            {
              Header: 'Network Out',
              accessor: 'networkOut',
            },
            {
              Header: 'Network Packets In',
              accessor: 'networkPacketsIn',
            },
            {
              Header: 'Network Packets Out',
              accessor: 'networkPacketsOut',
            },
            {
              Header: 'EBS IO Balance',
              accessor: 'EBSIOBalance',
            },

          ],
        },
      ],
      'costTable':[
        {
          Header: 'Basic Information',
          columns: [
            {
              Header: 'User ID',
              accessor: 'userId',
            },
            
          
          ],
        },
        {
          Header: 'Cost',
          columns: [
            {
              Header: 'Start Date',
              accessor: 'startDate',
            },
            {
              Header: 'End Date',
              accessor: 'endDate',
            },
            {
                Header: 'Amortized Cost',
                accessor: 'amortizedCost',
              },
              {
                Header: 'Unit',
                accessor: 'unit',
              }          
          ],
        },
      ],
      'latencyTable':[
        {
          Header: 'User Information',
          columns: [
            {
              Header: 'User ID',
              accessor: 'user_id',
            },
            {
              Header: 'userCity',
              accessor: 'userCity',
            },
            {
              Header: 'userIP',
              accessor: 'userIP',
            },
            {
              Header: 'userLatitude',
              accessor: 'userLatitude',
            },
            {
              Header: 'userLongitude',
              accessor: 'userLongitude',
            },
            
          
          ],
        },
        {
          Header: 'Instance Information',
          columns: [
            {
              Header: 'instanceid',
              accessor: 'instanceid',
            },
            {
              Header: 'instanceIP',
              accessor: 'instanceIP',
            },
            {
              Header: 'instanceCity',
              accessor: 'instanceCity',
            },
            {
              Header: 'instanceCountry',
              accessor: 'instanceCountry',
            },
            {
              Header: 'zone',
              accessor: 'zone',
            },
            {
              Header: 'region',
              accessor: 'region',
            },
              
          ],
        },
        {
          Header: 'Result',
          columns: [
            {
              Header: 'latency',
              accessor: 'latency',
            },
              
          ],
        },
      ]




}
export const Styles = styled.div`
padding: 1rem;

table {
  border-spacing: 0;
  border: 1px solid black;

  tr {
    :last-child {
      td {
        border-bottom: 0;
      }
    }
  }

  th,
  td {
    margin: 0;
    padding: 0.5rem;
    border-bottom: 1px solid black;
    border-right: 1px solid black;

    :last-child {
      border-right: 0;
    }
  }
}

.pagination {
  padding: 0.5rem;
}
`


const IndeterminateCheckbox = React.forwardRef(
    ({ indeterminate, ...rest }, ref) => {
      const defaultRef = React.useRef()
      const resolvedRef = ref || defaultRef
      // console.log("selected",resolvedRef)
      React.useEffect(() => {
        resolvedRef.current.indeterminate = indeterminate
      }, [resolvedRef, indeterminate])
  
      return (
        <>
          <input type="checkbox" ref={resolvedRef} {...rest} />
        </>
      )
    }
  )

const useInstance = (instance) => {
    // console.log("======instance",instance)

    if (instance && instance.getInstanceCallback) {
      if (instance.tableSelctedItem.length!=instance.selectedFlatRows.length)
      {  
        // console.log(instance)
        instance.getInstanceCallback(instance);
        }
    }
  };
export function Table({ columns, data,tableSelctedItem,getInstanceCallback}) {
    // Use the state and functions returned from useTable to build your UI
    const previousValue = useRef(null);
  
   
    const {
      getTableProps,
      getTableBodyProps,
      headerGroups,
      prepareRow,
      page, // Instead of using 'rows', we'll use page,
      // which has only the rows for the active page
  
      // The rest of these things are super handy, too ;)
      canPreviousPage,
      canNextPage,
      pageOptions,
      pageCount,
      gotoPage,
      nextPage,
      previousPage,
      setPageSize,
      selectedFlatRows,
      state: { pageIndex, pageSize, selectedRowIds },
    } = useTable(
      {
        columns,
        data,
        tableSelctedItem,
        getInstanceCallback
      },
      usePagination,
      useRowSelect,
      (hooks) => hooks.useInstance.push(useInstance),
      hooks => {
        hooks.visibleColumns.push(columns => [
          // Let's make a column for selection
          {
            id: 'selection',
            // The header can use the table's getToggleAllRowsSelectedProps method
            // to render a checkbox
            Header: ({ getToggleAllPageRowsSelectedProps }) => (
              <div>
                <IndeterminateCheckbox {...getToggleAllPageRowsSelectedProps()} />
              </div>
            ),
            // The cell can use the individual row's getToggleRowSelectedProps method
            // to the render a checkbox
            Cell: ({ row }) => (
              <div>
                <IndeterminateCheckbox {...row.getToggleRowSelectedProps()} />
              </div>
            ),
          },
          ...columns,
        ])
      }
    )
      
    useEffect(() => {
      previousValue.current = selectedRowIds;
    }, [selectedRowIds]);
    // Render the UI for your table
    return (
      <>
        {/* <pre>
          <code>
            {JSON.stringify(
              {
                pageIndex,
                pageSize,
                pageCount,
                canNextPage,
                canPreviousPage,
              },
              null,
              2
            )}
          </code>
        </pre> */}
        <table {...getTableProps()}>
          <thead>
            {headerGroups.map(headerGroup => (
              <tr {...headerGroup.getHeaderGroupProps()}>
                {headerGroup.headers.map(column => (
                  <th {...column.getHeaderProps()}>{column.render('Header')}</th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody {...getTableBodyProps()}>
            {page.map((row, i) => {
              prepareRow(row)
              return (
                <tr {...row.getRowProps()}>
                  {row.cells.map(cell => {
                    return <td {...cell.getCellProps()}>{cell.render('Cell')}</td>
                  })}
                </tr>
              )
            })}
          </tbody>
        </table>
        {/* 
          Pagination can be built however you'd like. 
          This is just a very basic UI implementation:
        */}
        <div className="pagination">
          <button onClick={() => gotoPage(0)} disabled={!canPreviousPage}>
            {'<<'}
          </button>{' '}
          <button onClick={() => previousPage()} disabled={!canPreviousPage}>
            {'<'}
          </button>{' '}
          <button onClick={() => nextPage()} disabled={!canNextPage}>
            {'>'}
          </button>{' '}
          <button onClick={() => gotoPage(pageCount - 1)} disabled={!canNextPage}>
            {'>>'}
          </button>{' '}
          <span>
            Page{' '}
            <strong>
              {pageIndex + 1} of {pageOptions.length}
            </strong>{' '}
          </span>
          <span>
            | Go to page:{' '}
            <input
              type="number"
              defaultValue={pageIndex + 1}
              onChange={e => {
                const page = e.target.value ? Number(e.target.value) - 1 : 0
                gotoPage(page)
              }}
              style={{ width: '100px' }}
            />
          </span>{' '}
          <select
            value={pageSize}
            onChange={e => {
              setPageSize(Number(e.target.value))
            }}
          >
            {[10, 20, 30, 40, 50].map(pageSize => (
              <option key={pageSize} value={pageSize}>
                Show {pageSize}
              </option>
            ))}
          </select>
          <pre>
            {/* <code>
              {JSON.stringify(
                {
                  selectedRowIds: selectedRowIds,
                  'selectedFlatRows[].original': selectedFlatRows.map(
                    d => d.original
                  ),
                },
                null,
                2
              )

             
              }
            </code> */}
          </pre>
        </div>
      </>
    )
  }
  