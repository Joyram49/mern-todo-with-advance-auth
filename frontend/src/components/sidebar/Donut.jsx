import { useState } from "react";
import Chart from "react-apexcharts";

const data = [
  { name: "pending", value: 25 },
  { name: "done", value: 75 },
];

const Donut = () => {
  const [chartOptions] = useState({
    colors: ["#142E15", "#3F9142"],
    chart: {
      height: 180,
      width: "100%",
      type: "donut",
    },
    labels: data.map((item) => item.name),
    series: data.map((item) => item.value),
    legend: {
      show: false,
    },
    stroke: {
      colors: ["transparent"],
    },
  });

  return (
    <div className=''>
      <div className='py-6' id='donut-chart'>
        <Chart
          options={chartOptions}
          series={chartOptions.series}
          type={chartOptions.chart.type}
          height={chartOptions.chart.height}
        />
        <div className='mt-4 flex justify-center gap-4'>
          {data.map((item, index) => (
            <div key={index} className='text-sm font-medium flex items-center'>
              <span
                className='inline-block w-3 h-3 mr-2 rounded-full'
                style={{
                  backgroundColor: chartOptions.colors?.[index] || "#000",
                }}
              ></span>
              {item.name} - {item.value}%
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Donut;
